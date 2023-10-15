#![recursion_limit = "128"]

// https://cprimozic.net/blog/writing-a-hashmap-to-struct-procedural-macro-in-rust/

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

// use proc_macro::TokenStream;
use proc_macro::Literal;
use syn::Ident; // , VariantData};
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Index, Path,
    Type,
};

#[derive(Debug)]
struct StructField {
    name: Ident,
    conv: Ident,
}

#[derive(Debug, Clone)]
struct NetprotoStructField {
    name: Ident,
    conv: Ident,
    add_conversion: bool,
    is_value: bool,
    ty: TokenStream,
    default: Option<TokenStream>,
    fill: Option<syn::Expr>,
    auto: Option<TokenStream>,
    encode: Option<syn::Expr>,
    decode: Option<syn::Expr>,
    next: Option<(syn::Ident, syn::Ident)>,
}

macro_rules! vec_newtype {
    ($name:ident, $inner_type:ident) => {
        $name
            .clone()
            .into_iter()
            .map($inner_type)
            .collect::<Vec<_>>()
    };
}

struct ImplDefaultNetprotoStructField(NetprotoStructField);
struct FieldMethodsNetprotoStructField(NetprotoStructField);
struct FillNetprotoStructField(NetprotoStructField);
struct EncodeNetprotoStructField(NetprotoStructField);
struct DecodeNetprotoStructField(NetprotoStructField);
struct ChainDecodeNetprotoStructField(NetprotoStructField);

use proc_macro2::{Punct, Spacing, Span, TokenStream, TokenTree};
use quote::{ToTokens, TokenStreamExt};

impl ToTokens for StructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.name.clone();
        let conv = self.conv.clone();
        let tk = quote! {
                     match hm.entry(String::from(stringify!(#name))) {
                         ::std::collections::hash_map::Entry::Occupied(occ_ent) => {
                             // set the corresponding struct field to the value in
                             // the corresponding hashmap if it contains it
                             out.#name = #conv(occ_ent.get().as_str());
                         },
                         ::std::collections::hash_map::Entry::Vacant(_) => (),
                     }
        };
        tokens.extend(tk);
    }
}
impl ToTokens for EncodeNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let tk2 = if self.0.is_value {
            quote! {
                let #varname: &#fixed_typ = &self.#name.value();
                out.extend_from_slice(&#varname.encode::<BinaryBigEndian>());
            }
        } else {
            quote! {
                let #varname: &#fixed_typ = &self.#name;
                out.extend_from_slice(&#varname.encode::<BinaryBigEndian>());
            }
        };

        let tk2 = if let Some(encode_expr) = &self.0.encode {
            if &encode_expr.to_token_stream().to_string() == "Skip" {
                quote! {}
            } else {
                quote! {
                    let #varname: Vec<u8> = #encode_expr::<BinaryBigEndian>(self, stack, my_index, encoded_data);
                    out.extend_from_slice(&#varname);
                }
            }
        } else {
            tk2
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for DecodeNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let tk2 = quote! {
            let (#varname, delta) = #fixed_typ::decode::<BinaryBigEndian>(&buf[ci..])?;
            ci += delta;
            layer = layer.#name(#varname);
        };
        let tk2 = if let Some(decode_expr) = &self.0.decode {
            if &decode_expr.to_token_stream().to_string() == "Skip" {
                quote! {}
            } else {
                quote! { #tk2 }
            }
        } else {
            quote! { #tk2 }
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for ChainDecodeNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let tk2 = if let Some((next_tbl, next_key)) = &self.0.next {
            let registry_lookup_name = Ident::new(
                &format!("{}_BY_{}", &next_tbl, &next_key),
                Span::call_site(),
            );
            quote! {
                if let Some(next) = (*#registry_lookup_name).get(&#varname) {
                    if let Some(decode) = (next.MakeLayer)().decode(&buf[ci..]) {
                        let mut down_layers = decode.layers;
                        layers.append(&mut down_layers);
                    } else {
                        let decode = self.decode_as_raw(&buf[ci..]);
                        let mut down_layers = decode.layers;
                        layers.append(&mut down_layers);
                    }
                } else {
                    let decode = self.decode_as_raw(&buf[ci..]);
                    let mut down_layers = decode.layers;
                    layers.append(&mut down_layers);
                }
            }
        } else {
            quote! {}
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for ImplDefaultNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let tk2 = quote! {
                #name: Self::#get_def_X(),
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for FillNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let fill_func = if let Some(fill_tok) = self.0.fill.clone() {
            let fill_expr = {
                match fill_tok {
                    syn::Expr::Path(ppp) => {
                        quote! {
                            #ppp(&out, stack, my_index)
                        }
                    }
                    x => {
                        quote! {
                            #x
                        }
                    }
                }
            };
            let set_statement = if self.0.add_conversion {
                quote! {
                    let #varname = #fill_expr;
                    out.#name = Value::Set(#varname.into());
                }
            } else {
                quote! {
                    let #varname = #fill_expr;
                    // out = out.#name(#varname);
                }
            };
            quote! {
                match &out.#name {
                    Value::Auto => {
                        // println!("XXX: #name {:?}", &out.#name);
                        #set_statement
                    },
                    Value::Random => {
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        let #varname: #fixed_typ = rng.gen();
                        out = out.#name(#varname);
                    },
                    Value::Func(x) => {
                        let #varname: #fixed_typ = x();
                        out = out.#name(#varname);
                    },
                    Value::Set(x) => {
                        // Already taken care by clone
                    }
                }
            }
        } else {
            if self.0.is_value {
                quote! {
                    match &out.#name {
                        Value::Auto => {
                            let #varname: #fixed_typ = Default::default();
                            out = out.#name(#varname);
                        },
                        Value::Func(x) => {
                            let #varname: #fixed_typ = x();
                            out = out.#name(#varname);
                        },
                        Value::Random => {
                            use rand::Rng;
                            let mut rng = rand::thread_rng();
                            let #varname: #fixed_typ = rng.gen();
                            out = out.#name(#varname);
                        },
                        Value::Set(x) => {
                            // Already taken care by clone
                        },
                    }
                }
            } else {
                quote! {
                    // non-Value fields are not auto-filled
                }
            }
        };

        let tk2 = quote! {
            #fill_func
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for FieldMethodsNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };

        let do_assignment_with_conversion = if self.0.is_value {
            quote! {
                pub fn #name<T: Into<#fixed_typ>>(mut self, #name: T) -> Self {
                    let #name: #fixed_typ = #name.into();
                    self.#name = Value::Set(#name);
                    self
                }
            }
        } else {
            quote! {
                pub fn #name<T: Into<#fixed_typ>>(mut self, #name: T) -> Self {
                    let #name: #fixed_typ = #name.into();
                    self.#name = #name;
                    self
                }
            }
        };
        let do_assignment_without_conversion = if self.0.is_value {
            quote! {
                pub fn #name(mut self, #name: #fixed_typ) -> Self {
                    self.#name = Value::Set(#name);
                    self
                }
            }
        } else {
            quote! {
                pub fn #name(mut self, #name: #typ) -> Self {
                    self.#name = #name;
                    self
                }
            }
        };

        let tk = if self.0.add_conversion {
            quote! {
                #do_assignment_with_conversion
            }
        } else {
            quote! {
                #do_assignment_without_conversion
            }
        };

        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());

        let def_val = if let Some(def_tok) = self.0.default.clone() {
            if self.0.add_conversion {
                if self.0.is_value {
                    // FIXME: it is not just "Random in the future"...
                    if def_tok.to_string() == "Random" {
                        quote! { #def_tok.into() }
                    } else {
                        quote! { Value::Set(#def_tok.into()) }
                    }
                } else {
                    quote! { #def_tok.into() }
                }
            } else {
                if self.0.is_value {
                    if def_tok.to_string() == "Random" {
                        quote! { #def_tok }
                    } else {
                        quote! { Value::Set(#def_tok) }
                    }
                } else {
                    quote! { #def_tok }
                }
            }
        } else {
            quote! { Default::default() }
        };

        let tk2 = quote! {

            pub fn #get_def_X() -> #typ {
                #def_val
            }

            pub fn #set_X(mut self, #name: #typ) -> Self {
                self.#name = #name;
                self
            }
        };

        tokens.extend(tk);
        tokens.extend(tk2);
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    let out = match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    };
    if &out == s {
        out.to_uppercase()
    } else {
        out
    }
}

#[derive(Debug, Clone)]
struct LayerRegistryEntry {
    name: syn::Ident,
    place: syn::Ident,
    key: syn::Ident,
    value: syn::Expr,
}

impl ToTokens for LayerRegistryEntry {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.name.clone();
        let macroname = Ident::new(&capitalize(&format!("{}", &name)), Span::call_site());
        let make_name_layer = Ident::new(&format!("make_{}_layer", &name), Span::call_site());
        let desc_name = Ident::new(&format!("{}_Item", &self.place), Span::call_site());
        let place = self.place.clone();
        let record_name = Ident::new(
            &format!("{}_{}_RegistrationRecord", &name, &place),
            Span::call_site(),
        );
        let key = self.key.clone();
        let value = self.value.clone();
        let tk = quote! {
            #[distributed_slice(#place)]
            static #record_name: #desc_name = #desc_name {
                Name: stringify!(#macroname),
                #key: #value,
                MakeLayer: #make_name_layer,
            };
        };
        tokens.extend(tk);
    }
}

#[derive(Debug, Clone)]
struct LayerRegistry {
    place: syn::Ident,
    key: syn::Ident,
    value: syn::Ident,
}
impl ToTokens for LayerRegistry {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let desc_name = Ident::new(&format!("{}_Item", &self.place), Span::call_site());
        let layers_by_key_name = Ident::new(
            &format!("{}_BY_{}", &self.place, &self.key),
            Span::call_site(),
        );
        let place = self.place.clone();
        let key = self.key.clone();
        let value = self.value.clone();
        let tk = quote! {
            #[derive(PartialEq, Clone, Eq, Debug)]
            pub struct #desc_name {
                pub Name: &'static str,
                pub #key: #value,
                pub MakeLayer: fn() -> Box<dyn Layer>,
            }
            #[distributed_slice]
            pub static #place: [#desc_name];

            lazy_static! {
                pub static ref #layers_by_key_name: HashMap<#value, #desc_name> = {
                    let mut m = HashMap::new();
                    for ll in #place {
                        m.insert(ll.#key, (*ll).clone());
                    }
                    m
                };
            }

        };
        tokens.extend(tk);
    }
}

#[proc_macro_derive(NetworkProtocol, attributes(nproto))]
pub fn network_protocol(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    use std::str::FromStr;
    use syn::{parenthesized, parse_quote, token, ItemStruct, LitInt, Token};

    let mut nproto_align = None::<usize>;
    let mut nproto_packed = None::<usize>;
    let mut nproto_register: Vec<LayerRegistryEntry> = vec![];
    let mut nproto_registries: Vec<LayerRegistry> = vec![];
    let default_encoder: TokenStream = "BinaryBigEndian".parse().unwrap();
    let default_decoder: TokenStream = "BinaryBigEndian".parse().unwrap();
    let mut nproto_encoder = default_encoder;
    let mut nproto_decoder = default_decoder;
    let mut nproto_decode_suppress = false;

    // let source = input.to_string();
    // Parse the string representation into a syntax tree
    // let ast = syn::parse_macro_input(&source).unwrap();
    //
    let input = syn::parse_macro_input!(input as DeriveInput);

    for attr in &input.attrs {
        let name = input.ident.clone();
        if attr.path().is_ident("nproto") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("decode_suppress") {
                    nproto_decode_suppress = true;
                    return Ok(());
                }
                // #[nproto(register(PLACE, Key = _expr_))
                if meta.path.is_ident("register") {
                    let content;
                    parenthesized!(content in meta.input);
                    println!("REGISTER: {:?}", &content);
                    let place: syn::Ident = content.parse()?;
                    println!("PLACE: {:?}", &place);
                    let comma_token: Option<Token![,]> = content.parse()?;
                    let key: syn::Ident = content.parse()?;
                    println!("KEY: {:?}", &key);
                    let eq_token: Option<Token![=]> = content.parse()?;
                    let value: syn::Expr = content.parse()?;
                    println!("VAL: {:?}", &value);
                    let name = name.clone();
                    nproto_register.push(LayerRegistryEntry {
                        name,
                        place,
                        key,
                        value,
                    });
                    return Ok(());
                }
                if meta.path.is_ident("registry") {
                    let content;
                    parenthesized!(content in meta.input);
                    println!("REGISTRY: {:?}", &content);
                    let place: syn::Ident = content.parse()?;
                    println!("PLACE: {:?}", &place);
                    let comma_token: Option<Token![,]> = content.parse()?;
                    let key: syn::Ident = content.parse()?;
                    println!("KEY: {:?}", &key);
                    let eq_token: Option<Token![:]> = content.parse()?;
                    let value: syn::Ident = content.parse()?;
                    println!("VAL: {:?}", &value);
                    let name = name.clone();
                    nproto_registries.push(LayerRegistry { place, key, value });
                    return Ok(());
                }
                // #[nproto(align(N))]
                if meta.path.is_ident("align") {
                    let content;
                    parenthesized!(content in meta.input);
                    let lit: LitInt = content.parse()?;
                    let n: usize = lit.base10_parse()?;
                    nproto_align = Some(n);
                    return Ok(());
                }

                // #[nproto(encoder(X))]
                if meta.path.is_ident("encoder") {
                    let content;
                    parenthesized!(content in meta.input);
                    let lit: syn::Type = content.parse()?;
                    if let syn::Type::Path(tt) = lit {
                        let encoder = tt.path.to_token_stream();
                        nproto_encoder = encoder;
                        return Ok(());
                    } else {
                        return Err(meta.error("bad encoder type"));
                    }
                }

                // #[nproto(packed)] or #[nproto(packed(N))], omitted N means 1
                if meta.path.is_ident("packed") {
                    if meta.input.peek(token::Paren) {
                        let content;
                        parenthesized!(content in meta.input);
                        let lit: LitInt = content.parse()?;
                        let n: usize = lit.base10_parse()?;
                        nproto_packed = Some(n);
                    } else {
                        nproto_packed = Some(1);
                    }
                    return Ok(());
                }

                return Err(meta.error("unrecognized nproto"));
            })
            .unwrap();
        }
    }

    let name = input.ident.clone();
    let macroname = Ident::new(&capitalize(&format!("{}", &name)), Span::call_site());
    let make_name_layer = Ident::new(&format!("make_{}_layer", &name), Span::call_site());
    let varname = Ident::new(&format!("__{}", &name), Span::call_site());

    let idents = netproto_struct_fields(&nproto_encoder, &input.data);
    let def_idents = vec_newtype!(idents, ImplDefaultNetprotoStructField);
    let field_methods_idents = vec_newtype!(idents, FieldMethodsNetprotoStructField);
    let fill_fields_idents = vec_newtype!(idents, FillNetprotoStructField);
    let encode_fields_idents = vec_newtype!(idents, EncodeNetprotoStructField);
    let decode_fields_idents = vec_newtype!(idents, DecodeNetprotoStructField);
    let chained_fields_idents = vec_newtype!(idents, ChainDecodeNetprotoStructField);

    let assign_in_macro = quote! {
                    // $ip.$ident = TryFrom::try_from($e).unwrap();
                    // $ip.$ident(TryFrom::try_from($e).unwrap().into());
                    $ip = $ip.$ident($e);
    };

    let decode_function = if nproto_decode_suppress {
        quote! {}
    } else {
        quote! {
            fn decode(&self, buf: &[u8]) -> Option<LayerStack> {
                use std::collections::HashMap;
                let mut ci: usize = 0;
                let mut layer = #macroname!();

                #(#decode_fields_idents)*

                let mut layers = vec![layer.embox()];

                #(#chained_fields_idents)*

                Some(LayerStack { layers })
            }
        }
    };

    let mut tokens = quote! {

        #( #nproto_registries )*

        #( #nproto_register )*

        impl<T: Layer> Div<T> for #name {
            type Output = LayerStack;
            fn div(mut self, rhs: T) -> Self::Output {
                let mut out = self.to_stack();
                out.layers.push(rhs.embox());
                out
            }
        }
        impl #name {
            pub fn of(stack: &LayerStack) -> Self {
                let res = &stack[TypeId::of::<Self>()];
                res.downcast_ref::<Self>().unwrap().clone()
            }

            #(
                    #field_methods_idents
            )*

        }

        fn #make_name_layer() -> Box<dyn Layer> {
            Box::new(#macroname!())
        }

        impl Default for #name {
            fn default() -> Self {
                #name {
                    #(
                        #def_idents
                    )*
                }
            }
        }


        impl Layer for #name {
            fn embox(self) -> Box<dyn Layer> {
                Box::new(self)
            }
            fn box_clone(&self) -> Box<dyn Layer> {
                Box::new((*self).clone())
            }
            fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack) {
                let mut out: #name = self.clone();
                #(#fill_fields_idents)*
                out_stack.layers.push(Box::new(out))
            }
            fn encode(&self, stack: &LayerStack, my_index: usize, encoded_data: &EncodingVecVec) -> Vec<u8> {
                let mut out: Vec<u8> = vec![];
                #(#encode_fields_idents)*
                out
            }
            #decode_function
        }


        #[macro_export]
        macro_rules! #macroname {
            () => {{
                {
                    let mut #varname: #name = Default::default();
                    #varname
                }
            }};

            ($ip:ident, $ident:ident=$e:expr) => {{
                {
                    #assign_in_macro
                }
            }};
            ($ip: ident, $ident:ident=$e:expr, $($x_ident:ident=$es:expr),+) => {{
                {
                    #macroname!($ip, $ident=$e);
                    #macroname!($ip, $($x_ident=$es),+);
                }
            }};

            ($ident:ident=$e:expr) => {{
                {
                    let mut #varname: #name = Default::default();
                    #macroname!(#varname, $ident=$e);
                    #varname
                }
            }};
            ($ident:ident=$e:expr, $($s_ident:ident=$es:expr),+) => {{
                {
                    let mut #varname = #macroname!($ident=$e);
                    #macroname!(#varname, $($s_ident=$es),+);
                    #varname
                }
            }};
            ($e:expr) => {{
                    let mut #varname: #name = Default::default();
                    #macroname!(#varname, data=$e);
                    #varname
            }};

        }


    };
    // eprintln!("{}", tokens.to_string());

    proc_macro::TokenStream::from(tokens)
}

#[proc_macro_derive(FromStringHashmap)]
pub fn from_string_hashmap(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // let source = input.to_string();
    // Parse the string representation into a syntax tree
    // let ast = syn::parse_macro_input(&source).unwrap();
    //
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    // create a vector containing the names of all fields on the struct
    let idents = struct_fields(&input.data);

    // contains quoted strings containing the struct fields in the same order as
    // the vector of idents.
    //
    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut tokens = quote! {
        impl #impl_generics FromStringHashmap<#name> for #name #ty_generics #where_clause {
            fn from_string_hashmap(mut hm: ::std::collections::HashMap<String, String>) -> #name {
                // start with the default implementation
                let mut out = #name::default();
                #(
                    #idents;
                )*
                // return the modified struct
                out
            }
        }
    };
    // eprintln!("{}", &tokens.to_string());

    proc_macro::TokenStream::from(tokens)
}

// Add a bound `T: HeapSize` to every type parameter T.
fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            // type_param.bounds.push(parse_quote!(heapsize::HeapSize));
        }
    }
    generics
}

// Generate an expression to sum up the heap size of each field.
fn struct_fields(data: &Data) -> Vec<StructField> {
    fn path_is_option(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Option"
    }
    fn path_is_value(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Value"
    }
    fn path_is_vec(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Vec"
    }

    let mut out = vec![];

    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    for f in &fields.named {
                        let name = f.ident.clone().unwrap();
                        // panic!("FIELD: {:#?}", f.ty);
                        match &f.ty {
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_option(&typepath.path) =>
                            {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_option"),
                                });
                            }
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_value(&typepath.path) =>
                            {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_value"),
                                });
                            }
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_vec(&typepath.path) =>
                            {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_vec"),
                                });
                            }
                            _ => {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair"),
                                });
                            }
                        }
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //     0 + self.0.heap_size() + self.1.heap_size() + self.2.heap_size()
                    /*
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index::from(i);
                        quote_spanned! {f.span()=>
                            heapsize::HeapSize::heap_size_of_children(&self.#index)
                        }
                    });
                    */
                }
                Fields::Unit => {}
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
    out
}

fn netproto_struct_fields(default_encoder: &TokenStream, data: &Data) -> Vec<NetprotoStructField> {
    fn path_is_option(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Option"
    }
    fn path_is_value(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Value"
    }
    fn path_is_vec(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Vec"
    }

    fn is_int_segment(seg: &syn::PathSegment) -> bool {
        use syn::PathArguments::AngleBracketed;
        if let AngleBracketed(ab) = &seg.arguments {
            if ab.args.len() == 1 {
                if let syn::GenericArgument::Type(syn::Type::Path(tp)) = &ab.args[0] {
                    let is_int = tp.path.segments.len() == 1
                        && tp
                            .path
                            .segments
                            .iter()
                            .next()
                            .unwrap()
                            .ident
                            .to_string()
                            .starts_with("u");
                    // println!("IS_INT: {} for {:?}", &is_int, &seg);
                    return is_int;
                }
            }
        }
        false
    }

    fn path_is_int(path: &Path) -> bool {
        (path.leading_colon.is_none()
            && path.segments.len() == 1
            && path
                .segments
                .iter()
                .next()
                .unwrap()
                .ident
                .to_string()
                .starts_with("u"))
            || (path.leading_colon.is_none()
                && path.segments.len() == 1
                && is_int_segment(path.segments.iter().next().unwrap()))
    }

    let mut out = vec![];

    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    for f in &fields.named {
                        let mut nproto_default = None::<TokenStream>;
                        let mut nproto_fill = None::<syn::Expr>;
                        let mut nproto_auto = None::<TokenStream>;
                        let mut nproto_encode = None::<syn::Expr>;
                        let mut nproto_next = None::<(syn::Ident, syn::Ident)>;
                        let mut nproto_decode = None::<syn::Expr>;
                        let name = f.ident.clone().unwrap();
                        // eprintln!("FIELD: {:#?}", f.ty);
                        for attr in &f.attrs {
                            use syn::{
                                braced, parenthesized, parse_quote, token, ItemStruct, LitInt,
                                Token,
                            };

                            let mut nproto_align = None::<usize>;
                            let mut nproto_packed = None::<usize>;
                            let mut nproto_encoder = default_encoder.clone();

                            if attr.path().is_ident("nproto") {
                                attr.parse_nested_meta(|meta| {
                                    // #[nproto(auto = _expr_)]
                                    if meta.path.is_ident("auto") {
                                        let eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_auto = Some(val_expr.to_token_stream());
                                        return Ok(());
                                    }

                                    if meta.path.is_ident("next") {
                                        let eq_token: Option<Token![:]> = meta.input.parse()?;
                                        let nxt: syn::Ident = meta.input.parse()?;
                                        let eq_token: Option<Token![=>]> = meta.input.parse()?;
                                        let nxt_key: syn::Ident = meta.input.parse()?;
                                        nproto_next = Some((nxt, nxt_key));
                                        return Ok(());
                                    }

                                    // #[nproto(encode = _expr_)]
                                    if meta.path.is_ident("encode") {
                                        let eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_encode = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(decode = _expr_)]
                                    if meta.path.is_ident("decode") {
                                        let eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_decode = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(fill = _expr_)]
                                    if meta.path.is_ident("fill") {
                                        let eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_fill = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(default = _expr_)]
                                    if meta.path.is_ident("default") {
                                        let eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_default = Some(val_expr.to_token_stream());
                                        return Ok(());
                                    }
                                    // #[nproto(align(N))]
                                    if meta.path.is_ident("align") {
                                        let content;
                                        parenthesized!(content in meta.input);
                                        let lit: LitInt = content.parse()?;
                                        let n: usize = lit.base10_parse()?;
                                        nproto_align = Some(n);
                                        return Ok(());
                                    }

                                    // #[nproto(encoder(X))]
                                    if meta.path.is_ident("encoder") {
                                        let content;
                                        parenthesized!(content in meta.input);
                                        let lit: syn::Type = content.parse()?;
                                        if let syn::Type::Path(tt) = lit {
                                            let encoder = tt.path.to_token_stream();
                                            nproto_encoder = encoder;
                                            return Ok(());
                                        } else {
                                            return Err(meta.error("bad encoder type"));
                                        }
                                    }

                                    // #[nproto(packed)] or #[nproto(packed(N))], omitted N means 1
                                    if meta.path.is_ident("packed") {
                                        if meta.input.peek(token::Paren) {
                                            let content;
                                            parenthesized!(content in meta.input);
                                            let lit: LitInt = content.parse()?;
                                            let n: usize = lit.base10_parse()?;
                                            nproto_packed = Some(n);
                                        } else {
                                            nproto_packed = Some(1);
                                        }
                                        return Ok(());
                                    }

                                    return Err(meta
                                        .error(format!("unrecognized nproto: {:?}", &meta.path)));
                                })
                                .unwrap();
                            }
                        }
                        match &f.ty {
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_option(&typepath.path) =>
                            {
                                out.push(NetprotoStructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_option"),
                                    add_conversion: !path_is_int(&typepath.path),
                                    is_value: true,
                                    ty: typepath.path.clone().to_token_stream(),
                                    default: nproto_default,
                                    auto: nproto_auto,
                                    fill: nproto_fill,
                                    encode: nproto_encode,
                                    next: nproto_next,
                                    decode: nproto_decode,
                                });
                            }
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_value(&typepath.path) =>
                            {
                                out.push(NetprotoStructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_value"),
                                    add_conversion: !path_is_int(&typepath.path),
                                    is_value: true,
                                    ty: typepath.path.clone().to_token_stream(),
                                    default: nproto_default,
                                    auto: nproto_auto,
                                    fill: nproto_fill,
                                    encode: nproto_encode,
                                    next: nproto_next,
                                    decode: nproto_decode,
                                });
                            }
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_vec(&typepath.path) =>
                            {
                                out.push(NetprotoStructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_vec"),
                                    add_conversion: !path_is_int(&typepath.path),
                                    is_value: false,
                                    ty: typepath.path.clone().to_token_stream(),
                                    default: nproto_default,
                                    auto: nproto_auto,
                                    fill: nproto_fill,
                                    encode: nproto_encode,
                                    next: nproto_next,
                                    decode: nproto_decode,
                                });
                            }
                            Type::Path(typepath) => {
                                out.push(NetprotoStructField {
                                    name,
                                    conv: format_ident!("parse_pair"),
                                    add_conversion: !path_is_int(&typepath.path),
                                    is_value: false,
                                    ty: typepath.path.clone().to_token_stream(),
                                    default: nproto_default,
                                    auto: nproto_auto,
                                    fill: nproto_fill,
                                    encode: nproto_encode,
                                    next: nproto_next,
                                    decode: nproto_decode,
                                });
                            }
                            _ => {
                                panic!("todo!");
                            }
                        }
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //     0 + self.0.heap_size() + self.1.heap_size() + self.2.heap_size()
                    /*
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index::from(i);
                        quote_spanned! {f.span()=>
                            heapsize::HeapSize::heap_size_of_children(&self.#index)
                        }
                    });
                    */
                }
                Fields::Unit => {}
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
    out
}

#[test]
fn test_fancy_repetition() {
    let foo = vec!["a", "b"];
    let bar = vec![true, false];

    let tokens = quote! {
        #(#foo: #bar),*
    };

    let expected = r#""a" : true , "b" : false"#;
    assert_eq!(expected, tokens.as_str());
}
