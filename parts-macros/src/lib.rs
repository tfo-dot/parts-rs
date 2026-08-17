use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn, FnArg, Pat, LitInt, Token, parse::{Parse, ParseStream}};

struct NativeFunctionAttr {
    arity: Option<u8>,
}

impl Parse for NativeFunctionAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut arity = None;
        if !input.is_empty() {
            let id: syn::Ident = input.parse()?;
            if id == "arity" {
                input.parse::<Token![=]>()?;
                let lit: LitInt = input.parse()?;
                arity = Some(lit.base10_parse()?);
            }
        }
        Ok(NativeFunctionAttr { arity })
    }
}

#[proc_macro_attribute]
pub fn native_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as NativeFunctionAttr);
    let input = parse_macro_input!(item as ItemFn);
    
    let name = &input.sig.ident;
    let vis = &input.vis;
    let body = &input.block;
    let sig_args = &input.sig.inputs;
    
    let arity = attr.arity.unwrap_or(sig_args.len() as u8);
    let internal_name = format_ident!("{}_internal", name);
    
    // Check if it's a "raw" function: fn(args: Vec<Value>)
    let is_raw = if sig_args.len() == 1 {
        if let FnArg::Typed(pat_type) = &sig_args[0] {
            if let Pat::Ident(pat_ident) = &*pat_type.pat {
                pat_ident.ident == "args"
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    let wrapper_body = if is_raw {
        quote! { #body }
    } else {
        let arg_extractions = sig_args.iter().enumerate().map(|(i, arg)| {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let arg_name = &pat_ident.ident;
                    quote! {
                        let #arg_name = args[#i].clone();
                    }
                } else {
                    quote! {}
                }
            } else {
                quote! {}
            }
        });
        
        quote! {
            if args.len() != #arity as usize {
                return Err(format!("Expected {} arguments, got {}", #arity, args.len()));
            }
            #(#arg_extractions)*
            #body
        }
    };

    let generated = quote! {
        #[allow(non_snake_case)]
        #vis fn #internal_name(args: Vec<crate::value::Value>) -> Result<crate::value::Value, String> {
            #wrapper_body
        }

        // ZMIANA: Zamiast 'pub const', generujemy funkcję zwracającą strukturę.
        #[allow(non_snake_case)]
        #vis fn #name() -> crate::value::NativeFunction {
            crate::value::NativeFunction {
                name: stringify!(#name),
                arity: #arity,
                // Pakujemy wygenerowaną funkcję internal w Rc
                call: std::sync::Arc::new(#internal_name), 
            }
        }
    };

    generated.into()
}
