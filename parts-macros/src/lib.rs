use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, FnArg, ItemFn, LitInt, Pat, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

struct NativeFunctionAttr {
    arity: Option<u8>,
    module: Option<String>,
    modules: Vec<String>,
    export: Option<String>,
    exports: Vec<String>,
    global: Option<bool>,
    globals: Vec<String>,
}

fn parse_string_list(input: ParseStream) -> syn::Result<Vec<String>> {
    let content;
    syn::bracketed!(content in input);
    let mut items = Vec::new();
    while !content.is_empty() {
        let s: syn::LitStr = content.parse()?;
        items.push(s.value());
        if content.peek(Token![,]) {
            content.parse::<Token![,]>()?;
        } else {
            break;
        }
    }
    Ok(items)
}

impl Parse for NativeFunctionAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attr = NativeFunctionAttr {
            arity: None,
            module: None,
            modules: Vec::new(),
            export: None,
            exports: Vec::new(),
            global: None,
            globals: Vec::new(),
        };
        while !input.is_empty() {
            let id: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            if id == "arity" {
                let lit: LitInt = input.parse()?;
                attr.arity = Some(lit.base10_parse()?);
            } else if id == "module" {
                let lit: syn::LitStr = input.parse()?;
                attr.module = Some(lit.value());
            } else if id == "modules" {
                attr.modules = parse_string_list(input)?;
            } else if id == "export" || id == "name" {
                let lit: syn::LitStr = input.parse()?;
                attr.export = Some(lit.value());
            } else if id == "exports" {
                attr.exports = parse_string_list(input)?;
            } else if id == "global" {
                let lit: syn::LitBool = input.parse()?;
                attr.global = Some(lit.value());
            } else if id == "globals" {
                attr.globals = parse_string_list(input)?;
            } else {
                return Err(syn::Error::new(
                    id.span(),
                    format!("unknown native_function attribute '{}'", id),
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }
        Ok(attr)
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

    // Check if it's a "raw" function: fn(args: &[Value]) or fn(args: Vec<Value>)
    let is_raw = if sig_args.len() == 1 {
        if let FnArg::Typed(pat_type) = &sig_args[0] {
            match &*pat_type.ty {
                syn::Type::Reference(_) => true,
                syn::Type::Path(type_path) => {
                    let seg = &type_path.path.segments.last().unwrap().ident;
                    seg == "Vec" || seg == "slice"
                }
                _ => false,
            }
        } else {
            false
        }
    } else {
        false
    };
    let wrapper_body = if is_raw {
        if let Some(expected_arity) = attr.arity {
            quote! {
                if args.len() != #expected_arity as usize {
                    return Err(format!("Expected {} arguments, got {}", #expected_arity, args.len()));
                }
                #body
            }
        } else {
            quote! { #body }
        }
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
        #vis fn #internal_name(args: &[crate::value::Value]) -> Result<crate::value::Value, String> {
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

extern crate proc_macro;

#[proc_macro_derive(IntoPartsObject)]
pub fn derive_into_parts_object(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let fields = match &ast.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("IntoPartsObject can only be derived for structs with named fields"),
        },
        _ => panic!("IntoPartsObject can only be derived for structs"),
    };

    let inserts = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_name_str = field_name.as_ref().unwrap().to_string();

        quote! {
            map.insert(
                ::parts::value::Value::String(#field_name_str.to_string().into()).get_hash(),
                ::parts::value::IntoValue::into_value(self.#field_name)
            );
        }
    });

    let expanded = quote! {
        impl ::parts::value::IntoValue for #name {
            fn into_value(self) -> ::parts::value::Value {
                let mut map = ::rustc_hash::FxHashMap::default();

                #(#inserts)*

                ::parts::value::Value::Object(::std::rc::Rc::new(::std::cell::RefCell::new(map)))
            }
        }
    };

    expanded.into()
}
#[proc_macro_derive(FromPartsObject)]
pub fn derive_from_parts_object(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let fields = match &ast.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("FromPartsObject can only be derived for structs with named fields"),
        },
        _ => panic!("FromPartsObject can only be derived for structs"),
    };

    let field_inits = fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_name_str = field_name.as_ref().unwrap().to_string();

        quote! {
            #field_name: ::parts::value::FromValue::from_value(&get_val(#field_name_str))?
        }
    });

    let expanded = quote! {
        impl ::parts::value::FromValue for #name {
            fn from_value(val: &::parts::value::Value) -> ::std::result::Result<Self, ::std::string::String> {
                if let ::parts::value::Value::Object(obj_ref) = val {
                    let obj = obj_ref.borrow();

                    let get_val = |key: &str| {
                        let hash = ::parts::value::Value::String(key.to_string().into()).get_hash();
                        obj.get(&hash).cloned().unwrap_or(::parts::value::Value::Bool(false))
                    };

                    ::std::result::Result::Ok(#name {
                        #(#field_inits),*
                    })
                } else {
                    ::std::result::Result::Err(::std::format!("Expected an object to map to {}", stringify!(#name)))
                }
            }
        }
    };

    expanded.into()
}

#[proc_macro_attribute]
pub fn parts_native(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a standard Rust function
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let block = &input_fn.block;
    let ret_type = &input_fn.sig.output;

    let mut arg_extractors = Vec::new();
    let mut arg_names = Vec::new();
    let mut arg_types = Vec::new();
    let arg_count = input_fn.sig.inputs.len();

    // Iterate over the function arguments (e.g., `url: String`)
    for (i, arg) in input_fn.sig.inputs.iter().enumerate() {
        if let syn::FnArg::Typed(pat_type) = arg {
            let pat = &pat_type.pat; // The variable name
            let ty = &pat_type.ty; // The variable type

            arg_names.push(pat.clone());
            arg_types.push(ty.clone());

            // Generate the FromValue extraction logic for this specific argument
            arg_extractors.push(quote! {
                let #pat = <#ty as ::parts::value::FromValue>::from_value(
                    args.get(#i).ok_or_else(|| ::std::format!("Missing argument at index {}", #i))?
                )?;
            });
        } else {
            panic!("self methods are not supported for native functions");
        }
    }

    // Generate the final wrapper function
    let expanded = quote! {
        #fn_vis fn #fn_name(args: &[::parts::value::Value]) -> ::std::result::Result<::parts::value::Value, ::std::string::String> {
            // 1. Validate argument count
            if args.len() < #arg_count {
                return ::std::result::Result::Err(::std::format!(
                    "{} requires {} arguments, but got {}",
                    ::std::stringify!(#fn_name),
                    #arg_count,
                    args.len()
                ));
            }

            // 2. Extract arguments into native Rust types
            #(#arg_extractors)*

            // 3. Define the original logic as an inner function to preserve type inference
            fn inner(#(#arg_names: #arg_types),*) #ret_type {
                #block
            }

            // 4. Execute the logic and pack the result into a parts Value
            let result = inner(#(#arg_names),*)?;
            ::std::result::Result::Ok(::parts::value::IntoValue::into_value(result))
        }
    };

    expanded.into()
}

struct StdConstAttr {
    module: String,
    export: Option<String>,
}

impl Parse for StdConstAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut module = None;
        let mut export = None;
        while !input.is_empty() {
            let id: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let lit: syn::LitStr = input.parse()?;
            if id == "module" {
                module = Some(lit.value());
            } else if id == "export" || id == "name" {
                export = Some(lit.value());
            } else {
                return Err(syn::Error::new(
                    id.span(),
                    format!("unknown std_const attribute '{}'", id),
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }
        let module = module.ok_or_else(|| {
            syn::Error::new(input.span(), "std_const requires `module = \"...\"`")
        })?;
        Ok(StdConstAttr { module, export })
    }
}

struct PartsStdAttr {
    overlays: Vec<(String, String)>,
}

impl Parse for PartsStdAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut overlays = Vec::new();
        while !input.is_empty() {
            let id: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            if id == "overlays" {
                let outer;
                syn::bracketed!(outer in input);
                while !outer.is_empty() {
                    let pair;
                    syn::parenthesized!(pair in outer);
                    let mod_path: syn::LitStr = pair.parse()?;
                    pair.parse::<Token![,]>()?;
                    let asset_path: syn::LitStr = pair.parse()?;
                    overlays.push((mod_path.value(), asset_path.value()));
                    if outer.peek(Token![,]) {
                        outer.parse::<Token![,]>()?;
                    } else {
                        break;
                    }
                }
            } else {
                return Err(syn::Error::new(
                    id.span(),
                    format!("unknown parts_std attribute '{}'", id),
                ));
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }
        Ok(PartsStdAttr { overlays })
    }
}

fn resolve_export_pairs(
    fn_name: &str,
    attr: &NativeFunctionAttr,
) -> syn::Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    let mut base_modules = Vec::new();
    if let Some(m) = &attr.module {
        base_modules.push(m.clone());
    }
    base_modules.extend(attr.modules.iter().cloned());

    if !attr.exports.is_empty() {
        for exp in &attr.exports {
            if let Some((mod_path, exp_name)) = exp.rsplit_once('.') {
                pairs.push((mod_path.to_string(), exp_name.to_string()));
            } else {
                if base_modules.is_empty() {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        format!(
                            "export '{}' in `exports` requires either `module`/`modules` or a dotted `module.export` path",
                            exp
                        ),
                    ));
                }
                for m in &base_modules {
                    pairs.push((m.clone(), exp.clone()));
                }
            }
        }
    } else if !base_modules.is_empty() {
        let exp_name = attr
            .export
            .clone()
            .unwrap_or_else(|| fn_name.to_string());
        for m in &base_modules {
            pairs.push((m.clone(), exp_name.clone()));
        }
    }
    Ok(pairs)
}

#[proc_macro_attribute]
pub fn parts_std(attr: TokenStream, item: TokenStream) -> TokenStream {
    let std_attr = parse_macro_input!(attr as PartsStdAttr);
    let mut input_mod = parse_macro_input!(item as syn::ItemMod);

    let (_, items) = match &mut input_mod.content {
        Some(content) => content,
        None => {
            return syn::Error::new_spanned(
                input_mod,
                "#[parts_std] requires an inline `mod { ... }`",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut global_stmts = Vec::new();
    let mut all_stmts = Vec::new();
    let mut module_export_stmts = Vec::new();
    let mut const_export_stmts = Vec::new();
    let mut overlay_stmts = Vec::new();

    for (mod_path, asset_path) in &std_attr.overlays {
        overlay_stmts.push(quote! {
            registry.set_overlay(#mod_path, #asset_path);
        });
    }

    for item in items.iter_mut() {
        match item {
            syn::Item::Fn(item_fn) => {
                let native_attr_opt = item_fn
                    .attrs
                    .iter()
                    .find(|a| a.path().is_ident("native_function"));

                if let Some(native_attr) = native_attr_opt {
                    let parsed = match &native_attr.meta {
                        syn::Meta::Path(_) => NativeFunctionAttr {
                            arity: None,
                            module: None,
                            modules: Vec::new(),
                            export: None,
                            exports: Vec::new(),
                            global: None,
                            globals: Vec::new(),
                        },
                        syn::Meta::List(list) => {
                            match syn::parse2::<NativeFunctionAttr>(list.tokens.clone()) {
                                Ok(a) => a,
                                Err(e) => return e.to_compile_error().into(),
                            }
                        }
                        _ => {
                            return syn::Error::new_spanned(
                                native_attr,
                                "invalid #[native_function] attribute syntax",
                            )
                            .to_compile_error()
                            .into();
                        }
                    };

                    let fn_ident = &item_fn.sig.ident;
                    let fn_name_str = fn_ident.to_string();
                    let internal_ident = format_ident!("{}_internal", fn_ident);

                    let export_pairs = match resolve_export_pairs(&fn_name_str, &parsed) {
                        Ok(p) => p,
                        Err(e) => return e.to_compile_error().into(),
                    };

                    let has_module = !export_pairs.is_empty();
                    let global_names: Vec<String> = if !parsed.globals.is_empty() {
                        parsed.globals.clone()
                    } else if parsed.global.unwrap_or(!has_module) {
                        vec![fn_name_str.clone()]
                    } else {
                        Vec::new()
                    };

                    let canonical_name = global_names
                        .first()
                        .cloned()
                        .unwrap_or_else(|| fn_name_str.clone());

                    let arity_expr = match parsed.arity {
                        Some(a) => quote! { #a },
                        None => {
                            let count = item_fn.sig.inputs.len() as u8;
                            quote! { #count }
                        }
                    };

                    let call_expr = quote! { std::sync::Arc::new(#internal_ident) };

                    for gname in &global_names {
                        global_stmts.push(quote! {
                            globals.push(crate::value::NativeFunction {
                                name: #gname,
                                arity: #arity_expr,
                                call: #call_expr,
                            });
                        });
                        all_stmts.push(quote! {
                            all.push(crate::value::NativeFunction {
                                name: #gname,
                                arity: #arity_expr,
                                call: #call_expr,
                            });
                        });
                    }

                    if !global_names.contains(&canonical_name) {
                        all_stmts.push(quote! {
                            all.push(crate::value::NativeFunction {
                                name: #canonical_name,
                                arity: #arity_expr,
                                call: #call_expr,
                            });
                        });
                    }

                    for (mod_path, exp_name) in export_pairs {
                        module_export_stmts.push(quote! {
                            registry.insert_native(
                                #mod_path,
                                #exp_name,
                                crate::value::NativeFunction {
                                    name: #canonical_name,
                                    arity: #arity_expr,
                                    call: #call_expr,
                                },
                            );
                        });
                    }
                }
            }
            syn::Item::Const(item_const) => {
                let mut found_const_attr = None;
                let mut remaining_attrs = Vec::with_capacity(item_const.attrs.len());
                for attr in item_const.attrs.drain(..) {
                    if attr.path().is_ident("std_const") {
                        found_const_attr = Some(attr);
                    } else {
                        remaining_attrs.push(attr);
                    }
                }
                item_const.attrs = remaining_attrs;

                if let Some(const_attr) = found_const_attr {
                    let parsed = match &const_attr.meta {
                        syn::Meta::List(list) => match syn::parse2::<StdConstAttr>(list.tokens.clone()) {
                            Ok(a) => a,
                            Err(e) => return e.to_compile_error().into(),
                        },
                        _ => {
                            return syn::Error::new_spanned(
                                const_attr,
                                "invalid #[std_const] attribute syntax",
                            )
                            .to_compile_error()
                            .into();
                        }
                    };
                    let const_ident = &item_const.ident;
                    let mod_path = parsed.module;
                    let exp_name = parsed
                        .export
                        .unwrap_or_else(|| const_ident.to_string());
                    let ty = &item_const.ty;
                    let ty_str = quote!(#ty).to_string();
                    let val_expr = match &**ty {
                        syn::Type::Path(tp) if tp.path.is_ident("f64") => {
                            quote! { crate::std::StdConstValue::Double(#const_ident) }
                        }
                        syn::Type::Path(tp) if tp.path.is_ident("i64") => {
                            quote! { crate::std::StdConstValue::Int(#const_ident) }
                        }
                        syn::Type::Path(tp) if tp.path.is_ident("bool") => {
                            quote! { crate::std::StdConstValue::Bool(#const_ident) }
                        }
                        syn::Type::Reference(_) => {
                            quote! { crate::std::StdConstValue::Str(#const_ident) }
                        }
                        _ => {
                            return syn::Error::new_spanned(
                                &item_const.ty,
                                format!("unsupported #[std_const] type: {}", ty_str),
                            )
                            .to_compile_error()
                            .into();
                        }
                    };
                    const_export_stmts.push(quote! {
                        registry.insert_const(#mod_path, #exp_name, #val_expr);
                    });
                }
            }
            _ => {}
        }
    }

    let registry_fn: syn::Item = syn::parse_quote! {
        pub fn build_std_data() -> (
            Vec<crate::value::NativeFunction>,
            Vec<crate::value::NativeFunction>,
            crate::std::StdRegistry,
        ) {
            let mut globals = Vec::new();
            let mut all = Vec::new();
            let mut registry = crate::std::StdRegistry::default();
            #(#global_stmts)*
            #(#all_stmts)*
            #(#module_export_stmts)*
            #(#const_export_stmts)*
            #(#overlay_stmts)*
            (globals, all, registry)
        }
    };
    items.push(registry_fn);

    quote! { #input_mod }.into()
}
