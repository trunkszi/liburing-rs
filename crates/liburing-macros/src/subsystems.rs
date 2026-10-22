//! Expand `define_subsystems!` into a fieldless subsystem enum.
//!
//! The generated tokens are plain Rust items: the enum, routing helpers,
//! conversion impls, and a const-range check. No runtime crate is named.

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::{AttrStyle, Attribute, Expr, Fields, ItemEnum, Lit, LitInt, Variant, ext::IdentExt};

/// One accepted unit variant, in source order.
struct DeclaredVariant {
    ident: syn::Ident,
    id: u8,
    id_literal: Literal,
    tokens: TokenStream,
}

/// Expands `define_subsystems!` into a `repr(u8)` subsystem enum.
///
/// The input is one enum item. Success yields that enum (with macro-supplied
/// derives and representation), `id` / `from_id` / `register_all`, `From` and
/// `TryFrom` impls, and a const assertion that every id is in `1..=255`.
/// Failure yields an error and no enum.
///
/// # Errors
///
/// Returns a spanned error when:
///
/// - `input` is not an enum item;
/// - the enum is generic or has a where clause;
/// - the enum has no variants;
/// - the enum or a variant already has a `derive` or `repr` attribute;
/// - the enum or a variant has a `cfg` or `cfg_attr` attribute;
/// - a variant name conflicts with a generated routing helper or conversion;
/// - a variant has fields;
/// - a variant has no discriminant, or the discriminant is not an integer literal (parentheses and
///   invisible groups around a single literal are accepted; arithmetic is not);
/// - an id is `0`, which is reserved for the proactor-internal waker/timer;
/// - an id is outside `1..=255`;
/// - two variants share an id (the error spans the later variant).
///
/// # Panics
///
/// This function does not panic.
pub fn expand(input: proc_macro2::TokenStream) -> syn::Result<proc_macro2::TokenStream> {
    let item = syn::parse2::<ItemEnum>(input)?;
    expand_enum(&item)
}

/// Validate `item` and render it, or return the first spanned error.
///
/// # Errors
///
/// Returns the same failures as [`expand`], except that a token stream which
/// is not an enum is rejected before this function is called.
///
/// # Panics
///
/// This function does not panic.
fn expand_enum(item: &ItemEnum) -> syn::Result<TokenStream> {
    reject_generics(item)?;
    reject_input_attributes(&item.attrs)?;
    let declared = collect_variants(item)?;
    Ok(render(item, &declared))
}

/// Reject type, lifetime, const, and where-clause generics.
///
/// # Errors
///
/// Returns an error spanning the generic parameter list when the enum is not
/// a plain item. Generated impls name the enum with no generic arguments.
///
/// # Panics
///
/// This function does not panic.
fn reject_generics(item: &ItemEnum) -> syn::Result<()> {
    let has_params = !item.generics.params.is_empty();
    let has_where = item.generics.where_clause.is_some();
    if !has_params && !has_where {
        return Ok(());
    }
    Err(syn::Error::new_spanned(
        &item.generics,
        "define_subsystems! does not support generic enums",
    ))
}

/// Reject macro-supplied and conditional attributes.
///
/// Conditional attributes cannot be retained on the enum alone: routing
/// helpers must reference exactly the variants present in the enum. Callers
/// can conditionally declare the entire macro invocation instead.
///
/// # Errors
///
/// Returns one error per `derive`, `repr`, `cfg`, or `cfg_attr` attribute.
/// The errors are combined so every offending attribute is reported together.
///
/// # Panics
///
/// This function does not panic.
fn reject_input_attributes(attrs: &[Attribute]) -> syn::Result<()> {
    let mut found: Option<syn::Error> = None;
    for attr in attrs {
        let Some(name) = forbidden_attribute_name(attr) else {
            continue;
        };
        let message = if matches!(name, "cfg" | "cfg_attr") {
            format!(
                "`#[{name}]` is not supported by define_subsystems!; conditionally declare the \
                 entire macro invocation instead"
            )
        } else {
            format!("`#[{name}]` is supplied by the macro and must not be written in the input")
        };
        let err = syn::Error::new_spanned(attr, message);
        found = Some(fold_error(found, err));
    }
    match found {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Combine `err` into an existing spanned error, or start a new one.
///
/// # Panics
///
/// This function does not panic.
fn fold_error(found: Option<syn::Error>, err: syn::Error) -> syn::Error {
    match found {
        Some(mut existing) => {
            existing.combine(err);
            existing
        }
        None => err,
    }
}

/// Return the name of an attribute unsupported in the macro input.
///
/// # Panics
///
/// This function does not panic.
fn forbidden_attribute_name(attr: &Attribute) -> Option<&'static str> {
    if attr.path().is_ident("derive") {
        Some("derive")
    } else if attr.path().is_ident("repr") {
        Some("repr")
    } else if attr.path().is_ident("cfg") {
        Some("cfg")
    } else if attr.path().is_ident("cfg_attr") {
        Some("cfg_attr")
    } else {
        None
    }
}

/// Split outer attributes from inner attributes.
///
/// Inner attributes, including inner doc comments, must be emitted inside the
/// enum body. Outer attributes stay in front of the item.
///
/// # Panics
///
/// This function does not panic.
fn split_attrs(attrs: &[Attribute]) -> (Vec<&Attribute>, Vec<&Attribute>) {
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    for attr in attrs {
        if matches!(attr.style, AttrStyle::Inner(_)) {
            inner.push(attr);
        } else {
            outer.push(attr);
        }
    }
    (outer, inner)
}

/// Parse every variant into a declared subsystem id.
///
/// # Errors
///
/// Returns an error when the enum is empty, or when the first invalid variant
/// has fields, a forbidden attribute, a missing or non-literal discriminant,
/// an id of `0`, an id outside `1..=255`, or an id already used by an earlier
/// variant.
///
/// # Panics
///
/// This function does not panic.
fn collect_variants(item: &ItemEnum) -> syn::Result<Vec<DeclaredVariant>> {
    if item.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "define_subsystems! rejects an empty enum",
        ));
    }
    let mut declared = Vec::new();
    for variant in &item.variants {
        let next = declare_variant(variant, &declared)?;
        declared.push(next);
    }
    Ok(declared)
}

/// Validate one variant and own the tokens that will be emitted for it.
///
/// # Errors
///
/// Returns a spanned error for a reserved name, fields, an unsupported attribute, a missing
/// or non-literal discriminant, id `0`, an id outside `1..=255`, or a
/// duplicate id. Duplicate errors span this later variant.
///
/// # Panics
///
/// This function does not panic.
fn declare_variant(
    variant: &Variant,
    declared: &[DeclaredVariant],
) -> syn::Result<DeclaredVariant> {
    reject_input_attributes(&variant.attrs)?;
    let name = variant.ident.unraw().to_string();
    if matches!(
        name.as_str(),
        "ALL" | "id" | "from_id" | "register_all" | "try_from"
    ) {
        return Err(syn::Error::new_spanned(
            &variant.ident,
            format!("subsystem variant `{name}` conflicts with a generated routing item"),
        ));
    }
    if !matches!(variant.fields, Fields::Unit) {
        return Err(syn::Error::new_spanned(
            variant,
            "subsystem variants must be unit variants",
        ));
    }
    let Some((_, expr)) = &variant.discriminant else {
        return Err(syn::Error::new_spanned(
            variant,
            "every subsystem variant needs an explicit integer-literal discriminant",
        ));
    };
    let int_lit = integer_literal(expr)?;
    let value = int_lit.base10_parse::<u64>()?;
    let id = match u8::try_from(value) {
        Ok(0) => {
            return Err(syn::Error::new_spanned(
                expr,
                "subsystem id 0 is reserved for the proactor-internal waker/timer",
            ));
        }
        Ok(id) => id,
        Err(_) => {
            return Err(syn::Error::new_spanned(
                expr,
                format!("subsystem id {value} is outside 1..=255"),
            ));
        }
    };
    if let Some(previous) = declared.iter().find(|earlier| earlier.id == id) {
        return Err(syn::Error::new_spanned(
            variant,
            format!(
                "duplicate subsystem id {id}, already used by `{}`",
                previous.ident
            ),
        ));
    }
    let id_literal = u8_literal(id, int_lit.span());
    let ident = variant.ident.clone();
    let attrs = &variant.attrs;
    let tokens = quote! {
        #(#attrs)*
        #ident = #id_literal,
    };
    Ok(DeclaredVariant {
        ident,
        id,
        id_literal,
        tokens,
    })
}

/// Peel parentheses and invisible groups until an integer literal remains.
///
/// # Errors
///
/// Returns an error spanning the discriminant expression when it is not an
/// integer literal. Implicit discriminants never reach this function.
/// Arithmetic and other operators are rejected here.
///
/// # Panics
///
/// This function does not panic.
fn integer_literal(expr: &Expr) -> syn::Result<&LitInt> {
    let mut current = expr;
    loop {
        match current {
            Expr::Group(group) => current = &group.expr,
            Expr::Paren(paren) => current = &paren.expr,
            Expr::Lit(lit) => match &lit.lit {
                Lit::Int(int_lit) => return Ok(int_lit),
                _ => break,
            },
            _ => break,
        }
    }
    Err(syn::Error::new_spanned(
        current,
        "subsystem discriminants must be integer literals; implicit discriminants and arithmetic \
         are not allowed",
    ))
}

/// Build a suffixed `u8` literal that keeps the source discriminant span.
///
/// # Panics
///
/// This function does not panic.
fn u8_literal(id: u8, span: proc_macro2::Span) -> Literal {
    let mut literal = Literal::u8_suffixed(id);
    literal.set_span(span);
    literal
}

/// Emit the enum and its routing items.
///
/// Callers pass only variants that already have distinct ids in `1..=255`.
///
/// # Panics
///
/// This function does not panic.
fn render(item: &ItemEnum, declared: &[DeclaredVariant]) -> TokenStream {
    let (outer_attrs, inner_attrs) = split_attrs(&item.attrs);
    let vis = &item.vis;
    let name = &item.ident;
    let id_param = syn::Ident::new("__uring_subsystem_id", proc_macro2::Span::mixed_site());
    let register_param = syn::Ident::new(
        "__uring_subsystem_register",
        proc_macro2::Span::mixed_site(),
    );
    let error_binding = syn::Ident::new("__uring_subsystem_error", proc_macro2::Span::mixed_site());
    let value_binding = syn::Ident::new("__uring_subsystem_value", proc_macro2::Span::mixed_site());
    let widened_binding =
        syn::Ident::new("__uring_subsystem_widened", proc_macro2::Span::mixed_site());
    let variant_tokens = declared.iter().map(|variant| &variant.tokens);
    let all_entries = declared.iter().map(|variant| {
        let ident = &variant.ident;
        quote!(Self::#ident)
    });
    let from_arms = declared.iter().map(|variant| {
        let ident = &variant.ident;
        let id_literal = &variant.id_literal;
        quote! {
            #id_literal => ::core::option::Option::Some(Self::#ident),
        }
    });
    // Spell the early return out without relying on the caller's prelude.
    let register_steps = declared.iter().map(|variant| {
        let ident = &variant.ident;
        quote! {
            match #register_param(Self::#ident) {
                ::core::result::Result::Ok(()) => {}
                ::core::result::Result::Err(#error_binding) => return ::core::result::Result::Err(#error_binding),
            }
        }
    });
    let assert_ids = declared.iter().map(|variant| {
        let ident = &variant.ident;
        let id_literal = &variant.id_literal;
        quote! {
            {
                let _: [(); 1] = [(); routing_id_in_range(#id_literal)];
                let _: [(); 1] = [(); routing_id_in_range(#name::#ident as ::core::primitive::u8)];
            }
        }
    });

    quote! {
        #(#outer_attrs)*
        #[derive(
            ::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug,
            ::core::cmp::PartialEq, ::core::cmp::Eq, ::core::hash::Hash,
        )]
        #[repr(u8)]
        #vis enum #name {
            #(#inner_attrs)*
            #(#variant_tokens)*
        }

        const _: () = {
            // Function items keep outer constants out of generated binding patterns.
            fn #id_param() {}
            fn #register_param() {}
            fn #error_binding() {}
            fn #value_binding() {}
            fn #widened_binding() {}
            let _ = (#id_param, #register_param, #error_binding, #value_binding, #widened_binding);

            /// Routing helpers for every declared subsystem.
            impl #name {
                /// Every declared subsystem, in source order.
                pub const ALL: &'static [Self] = &[#(#all_entries),*];

                /// Routing byte in 1..=255.
                ///
                /// # Panics
                ///
                /// This function does not panic.
                pub const fn id(self) -> ::core::primitive::u8 {
                    self as ::core::primitive::u8
                }

                /// Inverse of id. Returns None for 0 and for any undeclared id.
                ///
                /// # Panics
                ///
                /// This function does not panic.
                pub const fn from_id(#id_param: ::core::primitive::u8) -> ::core::option::Option<Self> {
                    match #id_param {
                        #(#from_arms)*
                        _ => ::core::option::Option::None,
                    }
                }

                /// Call register once per declared subsystem, in source order.
                ///
                /// Stops at the first error. Earlier callbacks are not rolled back.
                ///
                /// # Errors
                ///
                /// Returns the first error produced by register.
                ///
                /// # Panics
                ///
                /// Panics only if register panics.
                pub fn register_all<E>(
                    mut #register_param: impl ::core::ops::FnMut(Self) -> ::core::result::Result<(), E>,
                ) -> ::core::result::Result<(), E> {
                    #(#register_steps)*
                    ::core::result::Result::Ok(())
                }
            }

            /// Converts a subsystem into its routing byte.
            impl ::core::convert::From<#name> for ::core::primitive::u8 {
                /// Converts a subsystem into its routing byte in `1..=255`.
                ///
                /// # Panics
                ///
                /// This function does not panic.
                fn from(#value_binding: #name) -> ::core::primitive::u8 {
                    #value_binding.id()
                }
            }

            /// Converts a routing byte into a declared subsystem.
            impl ::core::convert::TryFrom<::core::primitive::u8> for #name {
                /// Byte that is `0` or not a declared subsystem.
                type Error = ::core::primitive::u8;

                /// Converts a routing byte into a subsystem.
                ///
                /// # Errors
                ///
                /// Returns `Err(id)` when `id` is `0` or is not a declared subsystem.
                ///
                /// # Panics
                ///
                /// This function does not panic.
                fn try_from(#id_param: ::core::primitive::u8) -> ::core::result::Result<Self, ::core::primitive::u8> {
                    match Self::from_id(#id_param) {
                        ::core::option::Option::Some(#value_binding) => ::core::result::Result::Ok(#value_binding),
                        ::core::option::Option::None => ::core::result::Result::Err(#id_param),
                    }
                }
            }

            // Each declared subsystem id must sit in 1..=255.
            const fn routing_id_in_range(#id_param: ::core::primitive::u8) -> ::core::primitive::usize {
                let #widened_binding: ::core::primitive::u16 = #id_param as ::core::primitive::u16;
                ((#widened_binding >= 1) && (#widened_binding <= 255)) as ::core::primitive::usize
            }
            #(#assert_ids)*
        };
    }
}

#[cfg(test)]
mod unit_tests {
    use quote::quote;

    #[test]
    fn unit_scenario_generated_routing_names_are_rejected_with_diagnostics() {
        for name in ["ALL", "id", "from_id", "register_all", "try_from"] {
            for spelling in [name.to_owned(), format!("r#{name}")] {
                let input = format!("enum Subsystems {{ {spelling} = 1 }}")
                    .parse::<proc_macro2::TokenStream>();
                let input = match input {
                    Ok(input) => input,
                    Err(error) => panic!("invalid test declaration: {error}"),
                };
                let error = match super::expand(input) {
                    Ok(_) => panic!("reserved routing name was accepted: {spelling}"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.to_string(),
                    format!("subsystem variant `{name}` conflicts with a generated routing item")
                );
                assert!(
                    error
                        .to_compile_error()
                        .to_string()
                        .contains("compile_error")
                );
            }
        }
        assert!(
            super::expand(quote! {
                enum Subsystems { All = 1, FromId = 2, id_next = 3, r#Network = 4 }
            })
            .is_ok()
        );
    }

    #[test]
    fn conditional_attributes_are_rejected_on_enums_and_variants() {
        let cases = [
            (
                quote!(
                    #[cfg(any())]
                    enum Subsystems {
                        Network = 1,
                    }
                ),
                "cfg",
            ),
            (
                quote!(
                    enum Subsystems {
                        #[cfg(any())]
                        Network = 1,
                    }
                ),
                "cfg",
            ),
            (
                quote!(
                    #[cfg_attr(any(), repr(u16))]
                    enum Subsystems {
                        Network = 1,
                    }
                ),
                "cfg_attr",
            ),
            (
                quote!(
                    enum Subsystems {
                        #[cfg_attr(any(), doc = "network")]
                        Network = 1,
                    }
                ),
                "cfg_attr",
            ),
        ];
        for (input, attribute) in cases {
            let error = match super::expand(input) {
                Ok(_) => panic!("conditional attribute was accepted"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "`#[{attribute}]` is not supported by define_subsystems!; conditionally \
                     declare the entire macro invocation instead"
                )
            );
        }
    }
}
