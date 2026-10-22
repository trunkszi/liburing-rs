//! Expansion of [`OpPayloadCodec`](crate::derive_op_payload_codec).

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Error, Expr, Fields, Ident, Index, Result, Type,
    Variant, spanned::Spanned,
};

const MAX_BITS: u32 = 56;
const MAX_RAW: u64 = 0x00FF_FFFF_FFFF_FFFF;

enum Layout {
    Fields {
        style: VariantStyle,
        fields: Vec<PackedField>,
    },
    Fieldless(Vec<Arm>),
    Tagged {
        tag_bits: u32,
        variants: Vec<TaggedArm>,
    },
}

struct PackedField {
    bits: u32,
    offset: u32,
    ty: Type,
    kind: FieldKind,
}

enum FieldKind {
    Named(Ident),
    Unnamed(Ident, Index),
}

struct Arm {
    name: Ident,
    discriminant: u64,
}

struct TaggedArm {
    name: Ident,
    tag: u64,
    style: VariantStyle,
    fields: Vec<PackedField>,
    field_bits: u32,
}

enum VariantStyle {
    Unit,
    Named,
    Unnamed,
}

/// Build the inherent payload codec for one derive input.
pub(crate) fn expand(input: TokenStream) -> Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            input.generics,
            "OpPayloadCodec does not support generic types",
        ));
    }
    let layout = match &input.data {
        Data::Struct(data) => {
            let (style, fields) = struct_fields(data)?;
            Layout::Fields { style, fields }
        }
        Data::Enum(data) => enum_layout(data)?,
        Data::Union(_) => {
            return Err(Error::new_spanned(
                input,
                "OpPayloadCodec does not support unions",
            ));
        }
    };
    let bits = layout_bits(&layout);
    if bits > MAX_BITS {
        return Err(Error::new(
            input.ident.span(),
            format!("OpPayloadCodec packed width is {bits} bits; the maximum is 56"),
        ));
    }
    Ok(render(&input.ident, bits, &layout))
}

fn layout_bits(layout: &Layout) -> u32 {
    match layout {
        Layout::Fields { fields, .. } => fields.iter().map(|field| field.bits).sum(),
        Layout::Fieldless(arms) => arms
            .iter()
            .map(|arm| value_bits(arm.discriminant))
            .max()
            .unwrap_or(0),
        Layout::Tagged { tag_bits, variants } => {
            let widest = variants
                .iter()
                .map(|variant| variant.field_bits)
                .max()
                .unwrap_or(0);
            tag_bits.saturating_add(widest)
        }
    }
}

fn struct_fields(data: &DataStruct) -> Result<(VariantStyle, Vec<PackedField>)> {
    let style = match &data.fields {
        Fields::Unit => VariantStyle::Unit,
        Fields::Named(_) => VariantStyle::Named,
        Fields::Unnamed(_) => VariantStyle::Unnamed,
    };
    Ok((style, pack_fields(&data.fields)?))
}

fn enum_layout(data: &DataEnum) -> Result<Layout> {
    if data.variants.is_empty() {
        return Err(Error::new_spanned(
            data.enum_token,
            "OpPayloadCodec requires at least one variant",
        ));
    }
    let data_carrying = data
        .variants
        .iter()
        .any(|variant| !matches!(variant.fields, Fields::Unit));
    if data_carrying {
        tagged_layout(data)
    } else {
        Ok(Layout::Fieldless(fieldless_arms(&data.variants)?))
    }
}

fn tagged_layout(data: &DataEnum) -> Result<Layout> {
    let tag_bits = tag_width(data.variants.len())?;
    let mut variants = Vec::new();
    for (index, variant) in data.variants.iter().enumerate() {
        if variant.discriminant.is_some() {
            return Err(Error::new_spanned(
                variant,
                "explicit discriminants require a fieldless enum",
            ));
        }
        let fields = pack_fields(&variant.fields)?;
        let field_bits = sum_bits(&fields).map_err(|error| Error::new(variant.span(), error))?;
        let style = match &variant.fields {
            Fields::Unit => VariantStyle::Unit,
            Fields::Named(_) => VariantStyle::Named,
            Fields::Unnamed(_) => VariantStyle::Unnamed,
        };
        variants.push(TaggedArm {
            name: variant.ident.clone(),
            tag: u64::try_from(index)
                .map_err(|_| Error::new_spanned(variant, "variant tag does not fit in 56 bits"))?,
            style,
            fields,
            field_bits,
        });
    }
    let total = tag_bits
        .checked_add(
            variants
                .iter()
                .map(|variant| variant.field_bits)
                .max()
                .unwrap_or(0),
        )
        .ok_or_else(|| Error::new_spanned(data.enum_token, "packed width overflows"))?;
    if total > MAX_BITS {
        return Err(Error::new_spanned(
            data.enum_token,
            format!("OpPayloadCodec packed width is {total} bits; the maximum is 56"),
        ));
    }
    Ok(Layout::Tagged { tag_bits, variants })
}

fn fieldless_arms<'a>(variants: impl IntoIterator<Item = &'a Variant>) -> Result<Vec<Arm>> {
    let mut next = 0u64;
    let mut overflowed = false;
    let mut arms: Vec<Arm> = Vec::new();
    for variant in variants {
        let discriminant = if let Some((_, expr)) = &variant.discriminant {
            literal_u64(expr)?
        } else if overflowed {
            return Err(Error::new_spanned(
                variant,
                "implicit discriminant overflows 64 bits",
            ));
        } else {
            next
        };
        if discriminant > MAX_RAW {
            return Err(Error::new_spanned(
                variant,
                "discriminant does not fit in 56 bits",
            ));
        }
        if arms.iter().any(|arm| arm.discriminant == discriminant) {
            return Err(Error::new_spanned(
                variant,
                "fieldless discriminants must be unique",
            ));
        }
        arms.push(Arm {
            name: variant.ident.clone(),
            discriminant,
        });
        match discriminant.checked_add(1) {
            Some(value) => next = value,
            None => overflowed = true,
        }
    }
    Ok(arms)
}

fn pack_fields(fields: &Fields) -> Result<Vec<PackedField>> {
    let mut packed = Vec::new();
    let mut offset = 0u32;
    for (index, field) in fields.iter().enumerate() {
        let bits = integer_bits(&field.ty)?;
        let kind = if let Some(name) = &field.ident {
            FieldKind::Named(name.clone())
        } else {
            let binding = Ident::new(&format!("field_{index}"), field.span());
            FieldKind::Unnamed(binding, Index::from(index))
        };
        packed.push(PackedField {
            bits,
            offset,
            ty: field.ty.clone(),
            kind,
        });
        offset = offset
            .checked_add(bits)
            .ok_or_else(|| Error::new_spanned(&field.ty, "OpPayloadCodec field widths overflow"))?;
    }
    if offset > MAX_BITS {
        return Err(Error::new_spanned(
            fields,
            format!("OpPayloadCodec packed width is {offset} bits; the maximum is 56"),
        ));
    }
    Ok(packed)
}

fn integer_bits(ty: &Type) -> Result<u32> {
    let Type::Path(path) = ty else {
        return Err(bad_field(ty));
    };
    if path.qself.is_some() {
        return Err(bad_field(ty));
    }
    let Some(segment) = path.path.segments.last() else {
        return Err(bad_field(ty));
    };
    if !segment.arguments.is_empty() {
        return Err(bad_field(ty));
    }
    match segment.ident.to_string().as_str() {
        "u8" => Ok(8),
        "u16" => Ok(16),
        "u32" => Ok(32),
        _ => Err(bad_field(ty)),
    }
}

fn bad_field(ty: &Type) -> Error {
    Error::new_spanned(ty, "OpPayloadCodec fields must be u8, u16, or u32")
}

fn literal_u64(expr: &Expr) -> Result<u64> {
    match expr {
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => value.base10_parse::<u64>(),
            _ => Err(Error::new_spanned(
                expr,
                "discriminant must be an integer literal",
            )),
        },
        Expr::Paren(inner) => literal_u64(&inner.expr),
        Expr::Group(inner) => literal_u64(&inner.expr),
        _ => Err(Error::new_spanned(
            expr,
            "discriminant must be an integer literal",
        )),
    }
}

fn tag_width(count: usize) -> Result<u32> {
    if count == 0 {
        return Err(Error::new(
            proc_macro2::Span::call_site(),
            "OpPayloadCodec requires at least one variant",
        ));
    }
    if count == 1 {
        return Ok(0);
    }
    Ok(usize::BITS - (count - 1).leading_zeros())
}

fn value_bits(value: u64) -> u32 {
    if value == 0 {
        0
    } else {
        u64::BITS - value.leading_zeros()
    }
}

fn sum_bits(fields: &[PackedField]) -> core::result::Result<u32, &'static str> {
    fields.iter().try_fold(0u32, |total, field| {
        total
            .checked_add(field.bits)
            .ok_or("OpPayloadCodec field widths overflow")
    })
}

fn render(name: &Ident, bits: u32, layout: &Layout) -> TokenStream {
    let encode = encode_body(layout);
    let decode = decode_body(bits, layout);
    quote! {
        impl #name {
            /// Number of low bits occupied by a packed payload.
            ///
            /// Every value returned by [`Self::encode_payload`] fits in this
            /// width and is at most `0x00FF_FFFF_FFFF_FFFF`.
            ///
            /// # Panics
            ///
            /// This constant cannot panic.
            pub const PAYLOAD_BITS: u32 = #bits;

            /// Pack `self` into the low [`Self::PAYLOAD_BITS`] bits of a `u64`.
            ///
            /// The upper 8 bits of the returned value are clear.
            ///
            /// # Panics
            ///
            /// This function does not panic.
            #[inline]
            #[must_use]
            pub const fn encode_payload(&self) -> u64 {
                #encode
            }

            /// Unpack a payload produced by [`Self::encode_payload`].
            ///
            /// # Errors
            ///
            /// Returns `Err(raw)` when any bit above the live payload is set,
            /// when the high 8 bits are set, or when `raw` is not a canonical
            /// encoding (unknown tag or unknown fieldless discriminant).
            ///
            /// # Panics
            ///
            /// This function does not panic.
            #[inline]
            #[must_use]
            pub const fn decode_payload(raw: u64) -> core::result::Result<Self, u64> {
                #decode
            }
        }

        const _: () = {
            assert!(#name::PAYLOAD_BITS <= 56);
        };
    }
}

fn encode_body(layout: &Layout) -> TokenStream {
    match layout {
        Layout::Fields { fields, .. } => {
            if fields.is_empty() {
                return quote! {
                    let _ = self;
                    0u64
                };
            }
            let stores = fields.iter().map(|field| {
                let read = field_read(field);
                let shifted = shift_left(quote!((#read as u64)), field.offset);
                quote! { raw |= #shifted; }
            });
            quote! {
                let mut raw = 0u64;
                #(#stores)*
                raw
            }
        }
        Layout::Fieldless(arms) => {
            let arms = arms.iter().map(|arm| {
                let name = &arm.name;
                let value = Literal::u64_unsuffixed(arm.discriminant);
                quote! { Self::#name => #value }
            });
            quote! {
                match self {
                    #(#arms,)*
                }
            }
        }
        Layout::Tagged { tag_bits, variants } => {
            let arms = variants
                .iter()
                .map(|variant| tagged_encode_arm(*tag_bits, variant));
            quote! {
                match self {
                    #(#arms,)*
                }
            }
        }
    }
}

fn tagged_encode_arm(tag_bits: u32, variant: &TaggedArm) -> TokenStream {
    let pattern = variant_pattern(variant);
    let tag = Literal::u64_unsuffixed(variant.tag);
    if variant.fields.is_empty() {
        return quote! { #pattern => #tag };
    }
    let copies = variant.fields.iter().map(|field| {
        let binding = field_binding(field);
        quote! { let #binding = *#binding as u64; }
    });
    let placed = variant.fields.iter().map(|field| {
        let binding = field_binding(field);
        let offset = tag_bits.saturating_add(field.offset);
        shift_left(quote!(#binding), offset)
    });
    quote! {
        #pattern => {
            #(#copies)*
            let mut raw = #tag;
            #(raw |= #placed;)*
            raw
        }
    }
}

fn decode_body(bits: u32, layout: &Layout) -> TokenStream {
    match layout {
        Layout::Fields { style, fields } => {
            let guard = high_guard(quote!(raw), bits);
            let locals = fields.iter().map(field_decode);
            let constructed = construct_struct(style, fields);
            quote! {
                #guard
                #(#locals)*
                core::result::Result::Ok(#constructed)
            }
        }
        Layout::Fieldless(arms) => {
            let arms = arms.iter().map(|arm| {
                let name = &arm.name;
                let value = Literal::u64_unsuffixed(arm.discriminant);
                quote! { #value => core::result::Result::Ok(Self::#name) }
            });
            quote! {
                if raw > 0x00FF_FFFF_FFFF_FFFFu64 {
                    return core::result::Result::Err(raw);
                }
                match raw {
                    #(#arms,)*
                    _ => core::result::Result::Err(raw),
                }
            }
        }
        Layout::Tagged { tag_bits, variants } => tagged_decode(*tag_bits, variants),
    }
}

fn tagged_decode(tag_bits: u32, variants: &[TaggedArm]) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let tag = Literal::u64_unsuffixed(variant.tag);
        let guard = high_guard(quote!(body), variant.field_bits);
        let locals = variant.fields.iter().map(|field| {
            let binding = field_binding(field);
            let ty = &field.ty;
            let masked = mask_shift(quote!(body), field.offset, field.bits);
            quote! { let #binding = (#masked) as #ty; }
        });
        let constructed = construct_variant(variant);
        quote! {
            #tag => {
                #guard
                #(#locals)*
                core::result::Result::Ok(#constructed)
            }
        }
    });
    let split = if tag_bits == 0 {
        quote! {
            let tag = 0u64;
            let body = raw;
        }
    } else {
        let mask = tag_mask(tag_bits);
        quote! {
            let tag = raw & #mask;
            let body = raw >> #tag_bits;
        }
    };
    let wildcard = if tag_bits == 0 {
        TokenStream::new()
    } else {
        quote! { _ => core::result::Result::Err(raw), }
    };
    quote! {
        if raw > 0x00FF_FFFF_FFFF_FFFFu64 {
            return core::result::Result::Err(raw);
        }
        #split
        match tag {
            #(#arms)*
            #wildcard
        }
    }
}

fn field_decode(field: &PackedField) -> TokenStream {
    let binding = field_binding(field);
    let ty = &field.ty;
    let masked = mask_shift(quote!(raw), field.offset, field.bits);
    quote! { let #binding = (#masked) as #ty; }
}

fn construct_struct(style: &VariantStyle, fields: &[PackedField]) -> TokenStream {
    let names = fields.iter().map(field_binding);
    match style {
        VariantStyle::Unit => quote!(Self),
        VariantStyle::Named => quote!(Self { #(#names),* }),
        VariantStyle::Unnamed => quote!(Self(#(#names),*)),
    }
}

fn construct_variant(variant: &TaggedArm) -> TokenStream {
    let name = &variant.name;
    match variant.style {
        VariantStyle::Unit => quote!(Self::#name),
        VariantStyle::Named => {
            let names = variant.fields.iter().map(field_binding);
            quote!(Self::#name { #(#names),* })
        }
        VariantStyle::Unnamed => {
            let names = variant.fields.iter().map(field_binding);
            quote!(Self::#name(#(#names),*))
        }
    }
}

fn variant_pattern(variant: &TaggedArm) -> TokenStream {
    let name = &variant.name;
    match variant.style {
        VariantStyle::Unit => quote!(Self::#name),
        VariantStyle::Named => {
            let names = variant.fields.iter().map(field_binding);
            quote!(Self::#name { #(#names),* })
        }
        VariantStyle::Unnamed => {
            let names = variant.fields.iter().map(field_binding);
            quote!(Self::#name(#(#names),*))
        }
    }
}

fn field_binding(field: &PackedField) -> Ident {
    match &field.kind {
        FieldKind::Named(name) | FieldKind::Unnamed(name, _) => name.clone(),
    }
}

fn field_read(field: &PackedField) -> TokenStream {
    match &field.kind {
        FieldKind::Named(name) => quote!(self.#name),
        FieldKind::Unnamed(_, index) => quote!(self.#index),
    }
}

fn shift_left(value: TokenStream, offset: u32) -> TokenStream {
    if offset == 0 {
        value
    } else {
        quote!((#value) << #offset)
    }
}

fn mask_shift(source: TokenStream, offset: u32, bits: u32) -> TokenStream {
    let mask = Literal::u64_suffixed(field_mask(bits));
    if offset == 0 {
        quote!((#source) & #mask)
    } else {
        quote!(((#source) >> #offset) & #mask)
    }
}

fn high_guard(source: TokenStream, bits: u32) -> TokenStream {
    if bits == 0 {
        quote! {
            if #source != 0 {
                return core::result::Result::Err(raw);
            }
        }
    } else {
        quote! {
            if (#source >> #bits) != 0 {
                return core::result::Result::Err(raw);
            }
        }
    }
}

fn field_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn tag_mask(tag_bits: u32) -> Literal {
    Literal::u64_unsuffixed(field_mask(tag_bits))
}
