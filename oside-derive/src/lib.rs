#![recursion_limit = "128"]
#![allow(nonstandard_style)]


// https://cprimozic.net/blog/writing-a-hashmap-to-struct-procedural-macro-in-rust/

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

// use proc_macro::TokenStream;
// use proc_macro::Literal;
use syn::Ident; // , VariantData};
use syn::{
    Data, DeriveInput, Fields, GenericParam, Generics, Path,
    Type,
};

#[derive(Debug)]
struct StructField {
    name: Ident,
    conv: Ident,
}
#[derive(Debug, Clone)]
struct NetprotoUnnamedField {
    ty: TokenStream,
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
    post_encode: Option<syn::Expr>,
    decode: Option<syn::Expr>,
    next: Option<(syn::Ident, syn::Ident)>,
    next_len_limit: Option<syn::Expr>,
    skip_encdec_unless: Option<syn::Expr>,
    set: Option<syn::Ident>,
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

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens};

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
        let _conv = self.0.conv.clone();
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };

        let encdec_condition = if let Some(skip_encdec_unless_expr) = &self.0.skip_encdec_unless {
            quote! { #skip_encdec_unless_expr }
        } else {
            quote! { true }
        };
            let pe2 = if let Some(post_encode_expr) = &self.0.post_encode {
                quote! {
                   #post_encode_expr::<EEE>(self, stack, my_index, &mut out, &skip_points, encoded_data);
                }
            } else {
                quote! {}
            };

        let tk2 = if self.0.is_value {
            quote! {
                let mut #varname: &#fixed_typ = &self.#name.value();
                out.extend_from_slice(&#varname.encode::<EEE>());
                #pe2
            }
        } else {
            quote! {
                let #varname: &#fixed_typ = &self.#name;
                out.extend_from_slice(&#varname.encode::<EEE>());
                #pe2
            }
        };

        let tk2 = if let Some(encode_expr) = &self.0.encode {
            if &encode_expr.to_token_stream().to_string() == "Skip" {
                quote! {
                    skip_points.push(out.len());
                }
            } else {
                quote! {
                    if (#encdec_condition) {
                        let #varname: Vec<u8> = #encode_expr::<EEE>(self, stack, my_index, encoded_data);
                        out.extend_from_slice(&#varname);
                        #pe2
                    }
                }
            }
        } else {
            quote! {
                if(#encdec_condition) {
                    #tk2
                }
            }
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for DecodeNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        use proc_macro2::{Punct, Spacing, TokenStream, TokenTree};

        fn insert_double_colon_if_second_is_angle_bracket(tokens: TokenStream) -> TokenStream {
            let mut token_vec: Vec<TokenTree> = tokens.into_iter().collect();

            if token_vec.len() > 1 {
                if let TokenTree::Punct(ref punct) = token_vec[1] {
                    if punct.as_char() == '<' {
                        // Create '::' token sequence
                        let first_colon = Punct::new(':', Spacing::Joint);
                        let second_colon = Punct::new(':', Spacing::Alone);

                        // Insert '::' after the first token
                        token_vec.insert(1, TokenTree::Punct(first_colon));
                        token_vec.insert(2, TokenTree::Punct(second_colon));
                    }
                }
            }

            // Convert Vec<TokenTree> back to TokenStream
            token_vec.into_iter().collect()
        }

        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let fixed_typ = insert_double_colon_if_second_is_angle_bracket(fixed_typ);

        let encdec_condition = if let Some(skip_encdec_unless_expr) = &self.0.skip_encdec_unless {
            quote! { #skip_encdec_unless_expr }
        } else {
            quote! { true }
        };

        let tk2 = quote! {
            let (#varname, delta) = if (#encdec_condition) {
                let (#varname, delta) = #fixed_typ::decode::<DDD>(&buf[ci..])?;
                ci += delta;
                (#varname, delta)
            } else {
                (Default::default(), 0)
            };
            layer = layer.#name(#varname);

        };
        let tk2 = if let Some(decode_expr) = &self.0.decode {
            if &decode_expr.to_token_stream().to_string() == "Skip" {
                quote! {}
            } else {
                quote! {
                    let (#varname, delta) = if (#encdec_condition) {
                        let (#varname, delta) = #decode_expr::<DDD>(&buf[..], ci, &mut layer)?;
                        ci += delta;
                        (#varname, delta)
                    } else {
                        (Default::default(), 0)
                    };
                    layer = layer.#name(#varname);
                }
            }
        } else {
            quote! {
                #tk2
            }
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for ChainDecodeNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());

        let tk2 = if let Some((next_tbl, next_key)) = &self.0.next {
            let registry_lookup_name = Ident::new(
                &format!("{}_BY_{}", &next_tbl, &next_key),
                Span::call_site(),
            );
            let next_range = if let Some(len_limit) = &self.0.next_len_limit {
                quote!{ ci..#len_limit }
            } else {
                quote!{ ci.. }
            };
            quote! {
                if let Some(next) = (*#registry_lookup_name).get(&#varname) {
                    if let Some((decode, delta)) = (next.MakeLayer)().ldecode(&buf[#next_range]) {
                        let mut down_layers = decode.layers;
                        layers.append(&mut down_layers);
                        ci += delta;
                    }
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
        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());

        let tk2 = quote! {
                #name: Self::#get_def_X(),
        };
        tokens.extend(tk2);
    }
}

impl ToTokens for FillNetprotoStructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let _ = self.0.auto; // silence the warning
        let name = self.0.name.clone();
        let varname = Ident::new(&format!("__{}", &name), Span::call_site());
        let typ = self.0.ty.clone();
        let fixed_typ: TokenStream = if self.0.is_value {
            let iter = typ.clone().into_iter().skip(2);
            let len = iter.clone().collect::<Vec<_>>().len();
            iter.take(len - 1).collect()
        } else {
            typ.clone()
        };
        let val_varname = Ident::new(&format!("__val_{}", &name), Span::call_site());
        // code to attempt to retrieve the next protocol id and set it into variable
        let try_set_by_next_layer = if let Some((next_tbl, next_key)) = &self.0.next {
            let typeid_registry_lookup_name =
                Ident::new(&format!("{}_BY_TYPEID", &next_tbl), Span::call_site());
            let typeid_varname = Ident::new(&format!("{}_typeid", &varname), Span::call_site());
            quote! {
                if my_index + 1 < stack.layers.len() {
                    let #typeid_varname = stack.layers[my_index + 1].get_layer_type_id();
                    if let Some(next) = (*#typeid_registry_lookup_name).get(&#typeid_varname) {
                        #val_varname = Value::Set(next.#next_key.clone());
                    }
                }
            }
        } else {
            quote! {}
        };

        let mut is_auto_fill = false;

        let fill_func = if let Some(fill_tok) = self.0.fill.clone() {
            let fill_expr = {
                match fill_tok {
                    syn::Expr::Path(ppp) => {
                        if ppp.clone().to_token_stream().to_string() == format!("auto") {
                           is_auto_fill = true;
                        }
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
            let set_statement = if is_auto_fill {
                // do nothing
                quote!{}
            } else {
                if self.0.add_conversion {
                quote! {
                    let #varname = #fill_expr;
                    out.#name = Value::Set(#varname.into());
                }
            } else {
                quote! {
                    let #varname = #fill_expr;
                    // out = out.#name(#varname);
                }
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
                            // try to set the auto field by the next level if possible
                            let mut #val_varname = Value::Auto;
                            #try_set_by_next_layer
                            let #varname: #fixed_typ = #val_varname.value();
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

        let derived_assignment_func = if self.0.add_conversion {
            quote! {
                #do_assignment_with_conversion
            }
        } else {
            quote! {
                #do_assignment_without_conversion
            }
        };

        let assignment_func = {
            if let Some(set_ident) = &self.0.set {
                quote! {
                    pub fn #name(mut self, #name: #typ) -> Self {
                        self = #set_ident(self, #name);
                        self
                    }
                }
            } else {
                quote! {
                    #derived_assignment_func
                }
            }
        };

        let get_def_X = Ident::new(&format!("get_default_{}", &name), Span::call_site());
        let set_X = Ident::new(&format!("set_{}", &name), Span::call_site());
        let modify_X = Ident::new(&format!("modify_{}", &name), Span::call_site());

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

            pub fn #modify_X(&mut self, #name: #typ) {
                self.#name = #name;
            }

            #assignment_func
        };

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
        let self_value_clone = self.value.clone();
        let self_value = quote! { #self_value_clone }.to_string();
        let reg_record_string = format!("{}_{}_{}_{}_RegistrationRecord", &name, &place, &self.key, &self_value)
            .replace(|c: char| !c.is_alphanumeric(), "_");
        let record_name = Ident::new(
            &reg_record_string,
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
    value: syn::Type,
}
impl ToTokens for LayerRegistry {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let desc_name = Ident::new(&format!("{}_Item", &self.place), Span::call_site());
        let layers_by_key_name = Ident::new(
            &format!("{}_BY_{}", &self.place, &self.key),
            Span::call_site(),
        );
        let layers_by_TYPEID = Ident::new(&format!("{}_BY_TYPEID", &self.place), Span::call_site());
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
                pub static ref #layers_by_TYPEID: HashMap<TypeId, #desc_name> = {
                    let mut m = HashMap::new();
                    for ll in #place {
                        let ti = (ll.MakeLayer)().get_layer_type_id();
                        m.insert(ti, (*ll).clone());
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
    // use std::str::FromStr;
    use syn::{parenthesized, token, LitInt, Token};

    let mut nproto_align = None::<usize>;
    let mut nproto_packed = None::<usize>;
    let mut nproto_register: Vec<LayerRegistryEntry> = vec![];
    let mut nproto_registries: Vec<LayerRegistry> = vec![];
    let default_encoder: TokenStream = "BinaryBigEndian".parse().unwrap();
    let default_decoder: TokenStream = "BinaryBigEndian".parse().unwrap();
    let mut nproto_encoder = default_encoder;
    let mut _nproto_decoder = default_decoder;
    let mut nproto_decode_suppress = false;
    let mut nproto_encode_suppress = false;
    let mut nproto_greedy_decode = true;

    let mut pre_decode: Option<syn::Expr> = None;
    let mut post_decode: Option<syn::Expr> = None;

    let mut decoder_type: Option<syn::Ident> = None;
    let mut encoder_type: Option<syn::Ident> = None;

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
                if meta.path.is_ident("encode_suppress") {
                    nproto_encode_suppress = true;
                    return Ok(());
                }
                // #[nproto(pre_decode= ... )]
                if meta.path.is_ident("pre_decode") {
                    let _eq_token: Option<Token![=]> = meta.input.parse()?;
                    let val_expr: syn::Expr = meta.input.parse()?;
                    // pre_decode = Some(val_expr.to_token_stream());
                    pre_decode = Some(val_expr);
                    return Ok(());
                }
                // #[nproto(post_decode= ... )]
                if meta.path.is_ident("post_decode") {
                    let _eq_token: Option<Token![=]> = meta.input.parse()?;
                    let val_expr: syn::Expr = meta.input.parse()?;
                    // pre_decode = Some(val_expr.to_token_stream());
                    post_decode = Some(val_expr);
                    return Ok(());
                }
                // #[nproto(decoder= ... )]
                if meta.path.is_ident("decoder") {
                    let content;
                    parenthesized!(content in meta.input);
                    let val_expr: syn::Ident = content.parse()?;
                    decoder_type = Some(val_expr);
                    return Ok(());
                }
                // #[nproto(decoder= ... )]
                if meta.path.is_ident("encoder") {
                    let content;
                    parenthesized!(content in meta.input);
                    let val_expr: syn::Ident = content.parse()?;
                    encoder_type = Some(val_expr);
                    return Ok(());
                }
                // #[nproto(register(PLACE, Key = _expr_))
                if meta.path.is_ident("register") {
                    let content;
                    parenthesized!(content in meta.input);
                    // println!("REGISTER: {:?}", &content);
                    let place: syn::Ident = content.parse()?;
                    // println!("PLACE: {:?}", &place);
                    let _comma_token: Option<Token![,]> = content.parse()?;
                    let key: syn::Ident = content.parse()?;
                    // println!("KEY: {:?}", &key);
                    let _eq_token: Option<Token![=]> = content.parse()?;
                    let value: syn::Expr = content.parse()?;
                    // println!("VAL: {:?}", &value);
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
                    // println!("REGISTRY: {:?}", &content);
                    let place: syn::Ident = content.parse()?;
                    // println!("PLACE: {:?}", &place);
                    let _comma_token: Option<Token![,]> = content.parse()?;
                    let key: syn::Ident = content.parse()?;
                    // println!("KEY: {:?}", &key);
                    let _eq_token: Option<Token![:]> = content.parse()?;
                    let value: syn::Type = content.parse()?;
                    // println!("VAL: {:?}", &value);
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
                // #[nproto(greedy_decode)]
                if meta.path.is_ident("non_greedy_decode") {
                    if meta.input.peek(token::Paren) {
                        let content;
                        parenthesized!(content in meta.input);
                        let lit: LitInt = content.parse()?;
                        let _n: usize = lit.base10_parse()?;
                        nproto_greedy_decode = false;
                    } else {
                        nproto_greedy_decode = false;
                    }
                    return Ok(());
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

    let (idents, unnamed_idents) = netproto_struct_fields(&nproto_encoder, &input.data);
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

    let default_value = if unnamed_idents.len() > 0 {
        let subtype = unnamed_idents[0].ty.clone();
        quote! {
                #name (#subtype::default())
        }
    } else {
        quote! {
                #name {
                    #(
                        #def_idents
                    )*
                }
        }
    };

    let unnamed_encode_expr = if unnamed_idents.len() > 0 {
        quote! {
            out = self.0.lencode(stack, my_index, encoded_data);
        }
    } else {
        quote! {}
    };

    let unnamed_decode_expr = if unnamed_idents.len() > 0 {
        let subtype = unnamed_idents[0].ty.clone();
        quote! {
                    if let Some((dec, delta)) = self.0.ldecode(&buf) {
                        layers[0].downcast_mut::<#name>().unwrap().0 = dec.layers[0].downcast_ref::<#subtype>().unwrap().clone();
                        let mut down_layers = dec.layers[1..].to_vec();
                        layers.append(&mut down_layers);
                        ci += delta;
                    } else {
                        return None;
                    }
        }
    } else {
        quote! {}
    };


    let greedy_decode_code = if nproto_greedy_decode {
        quote! {
                if ci < buf.len() {
                    let decode = self.decode_as_raw(&buf[ci..]);
                    let mut down_layers = decode.layers;
                    layers.append(&mut down_layers);
                    ci += buf.len() - ci;
                }
        }
    } else {
        quote! {}
    };

    let pre_decode_code = if let Some(pre_decode) = pre_decode {
        quote! { #pre_decode }
    } else {
        quote! {}
    };

    let decoder_ident = if let Some(decoder_type) = decoder_type {
        decoder_type
    } else {
        Ident::new(&format!("BinaryBigEndian"), Span::call_site())
    };

    let encoder_ident = if let Some(encoder_type) = encoder_type {
        encoder_type
    } else {
        Ident::new(&format!("BinaryBigEndian"), Span::call_site())
    };

    let post_decode_code = if let Some(post_decode) = post_decode {
        quote! { #post_decode }
    } else {
        quote! {}
    };

    let decode_function = if nproto_decode_suppress {
        quote! {}
    } else {
        quote! {
            fn ldecode(&self, buf: &[u8]) -> Option<(LayerStack, usize)> {
                type DDD = #decoder_ident;
                use std::collections::HashMap;
                let mut ci: usize = 0;
                let mut layer = #macroname!();
                let mut max_len = buf.len();

                if let Some((new_len, delta)) = DDD::pre_decode_seq(buf, buf.len()) {
                    max_len = new_len;
                    ci += delta;
                }

                #pre_decode_code

                #(#decode_fields_idents)*


                let mut layers = vec![layer.embox()];

                #(#chained_fields_idents)*

                #unnamed_decode_expr

                #greedy_decode_code

                #post_decode_code

                Some((LayerStack { layers, filled: true }, ci))
            }
        }
    };
    let encode_function = if nproto_encode_suppress {
        quote! {}
    } else {
        quote! {
            fn lencode(&self, stack: &LayerStack, my_index: usize, encoded_data: &EncodingVecVec) -> Vec<u8> {
                let layer = self;
                type EEE = #encoder_ident;
                let mut out: Vec<u8> = vec![];
                let mut skip_points: Vec<usize> = vec![];
                #(#encode_fields_idents)*

                #unnamed_encode_expr

                out
            }
        }
    };

    let tokens = quote! {

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

        impl Decode for #name {
            fn decode<DDD: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
                use std::collections::HashMap;
                let mut ci: usize = 0;
                let mut layer = #macroname!();

                #(#decode_fields_idents)*


                Some((layer, ci))
            }
        }

        impl Encode for #name {
            fn encode<EEE: Encoder>(&self) -> Vec<u8> {
                let layer = self;
                // Mock values appease the function-based encoders - which should not be used
                let encoded_data = EncodingVecVec::default();
                let encoded_data = &encoded_data;
                let stack = LayerStack::default();
                let stack = &stack;
                let my_index = 0;
                let mut out: Vec<u8> = vec![];
                let mut skip_points: Vec<usize> = vec![];
                #(#encode_fields_idents)*
                out
            }
        }



        impl #name {
            fn encode_with_encoder<EEE: Encoder>(&self, stack: &LayerStack, my_index: usize, encoded_data: &EncodingVecVec) -> Vec<u8> {
                let layer = self;
                let mut out: Vec<u8> = vec![];
                let mut skip_points: Vec<usize> = vec![];
                #(#encode_fields_idents)*
                out
            }
            fn decode_with_decoder<DDD: Decoder>(&self, buf: &[u8]) -> Option<(LayerStack, usize)> {
                use std::collections::HashMap;
                let mut ci: usize = 0;
                let mut layer = #macroname!();

                #(#decode_fields_idents)*

                let mut layers = vec![layer.embox()];

                #(#chained_fields_idents)*

                #greedy_decode_code

                Some((LayerStack { layers, filled: true }, ci))
            }

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
                #default_value
            }
        }

        #[typetag::serde]
        impl Layer for #name {
            fn embox(self) -> Box<dyn Layer> {
                Box::new(self)
            }
            fn box_clone(&self) -> Box<dyn Layer> {
                Box::new((*self).clone())
            }
            fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack) {
                let mut out: #name = self.clone();
                let mut skip_points: Vec<usize> = vec![];
                #(#fill_fields_idents)*
                out_stack.layers.push(Box::new(out))
            }

            #encode_function

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

    let tokens = quote! {
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
        if let GenericParam::Type(ref mut _type_param) = *param {
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
                Fields::Unnamed(ref _fields) => {
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

fn netproto_struct_fields(default_encoder: &TokenStream, data: &Data) -> (Vec<NetprotoStructField>, Vec<NetprotoUnnamedField>) {
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
    let mut unnamed_out = vec![];

    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    for f in &fields.named {
                        let mut nproto_default = None::<TokenStream>;
                        let mut nproto_fill = None::<syn::Expr>;
                        let mut nproto_auto = None::<TokenStream>;
                        let mut nproto_encode = None::<syn::Expr>;
                        let mut nproto_post_encode = None::<syn::Expr>;
                        let mut nproto_next = None::<(syn::Ident, syn::Ident)>;
                        let mut nproto_next_len_limit = None::<syn::Expr>;
                        let mut nproto_decode = None::<syn::Expr>;
                        let mut nproto_skip_encdec_unless = None::<syn::Expr>;
                        let mut nproto_set = None::<syn::Ident>;
                        let name = f.ident.clone().unwrap();
                        // eprintln!("FIELD: {:#?}", f.ty);
                        for attr in &f.attrs {
                            use syn::{
                                parenthesized, token, LitInt,
                                Token,
                            };

                            let mut nproto_align = None::<usize>;
                            let mut nproto_packed = None::<usize>;
                            let mut nproto_encoder = default_encoder.clone();

                            if attr.path().is_ident("nproto") {
                                attr.parse_nested_meta(|meta| {
                                    // #[nproto(skip_encdec_unless(_expr_))]
                                    if meta.path.is_ident("skip_encdec_unless") {
                                        let content;
                                        parenthesized!(content in meta.input);
                                        let val_expr: syn::Expr = content.parse()?;
                                        nproto_skip_encdec_unless = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(auto = _expr_)]
                                    if meta.path.is_ident("auto") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_auto = Some(val_expr.to_token_stream());
                                        return Ok(());
                                    }

                                    // #[nproto(set = _ident_)]
                                    if meta.path.is_ident("set") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_ident: syn::Ident = meta.input.parse()?;
                                        nproto_set = Some(val_ident);
                                        return Ok(());
                                    }

                                    if meta.path.is_ident("next") {
                                        let _eq_token: Option<Token![:]> = meta.input.parse()?;
                                        let nxt: syn::Ident = meta.input.parse()?;
                                        let _eq_token: Option<Token![=>]> = meta.input.parse()?;
                                        let nxt_key: syn::Ident = meta.input.parse()?;
                                        nproto_next = Some((nxt, nxt_key));
                                        return Ok(());
                                    }

                                    // #[nproto(next_len = _expr_)]
                                    if meta.path.is_ident("next_len") {

                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_next_len_limit = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(encode = _expr_)]
                                    if meta.path.is_ident("encode") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_encode = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(post_encode = _expr_)]
                                    if meta.path.is_ident("post_encode") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_post_encode = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(decode = _expr_)]
                                    if meta.path.is_ident("decode") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_decode = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(fill = _expr_)]
                                    if meta.path.is_ident("fill") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
                                        let val_expr: syn::Expr = meta.input.parse()?;
                                        nproto_fill = Some(val_expr);
                                        return Ok(());
                                    }

                                    // #[nproto(default = _expr_)]
                                    if meta.path.is_ident("default") {
                                        let _eq_token: Option<Token![=]> = meta.input.parse()?;
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
                                    post_encode: nproto_post_encode,
                                    next: nproto_next,
                                    next_len_limit: nproto_next_len_limit,
                                    decode: nproto_decode,
                                    skip_encdec_unless: nproto_skip_encdec_unless,
                                    set: nproto_set,
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
                                    post_encode: nproto_post_encode,
                                    next: nproto_next,
                                    next_len_limit: nproto_next_len_limit,
                                    decode: nproto_decode,
                                    skip_encdec_unless: nproto_skip_encdec_unless,
                                    set: nproto_set,
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
                                    post_encode: nproto_post_encode,
                                    next: nproto_next,
                                    next_len_limit: nproto_next_len_limit,
                                    decode: nproto_decode,
                                    skip_encdec_unless: nproto_skip_encdec_unless,
                                    set: nproto_set,
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
                                    post_encode: nproto_post_encode,
                                    next: nproto_next,
                                    next_len_limit: nproto_next_len_limit,
                                    decode: nproto_decode,
                                    skip_encdec_unless: nproto_skip_encdec_unless,
                                    set: nproto_set,
                                });
                            }
                            _ => {
                                panic!("todo!");
                            }
                        }
                    }
                }
                Fields::Unnamed(ref fields) => {
                    for f in &fields.unnamed {
                        unnamed_out.push(NetprotoUnnamedField {
                            ty: f.ty.clone().to_token_stream(),
                        });
                    }
                }
                Fields::Unit => {
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
    (out, unnamed_out)
}

fn debug_print_generated(ast: &DeriveInput, toks: &TokenStream) {
    let debug = std::env::var("STRUM_DEBUG");
    if let Ok(s) = debug {
        if s == "1" {
            println!("{}", toks);
        }

        if ast.ident == s {
            println!("{}", toks);
        }
    }
}

// The enum logic from https://github.com/Peternator7/strum/tree/master

mod from_repr;

#[proc_macro_derive(FromRepr)]
pub fn from_repr(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as DeriveInput);

    let toks = from_repr::from_repr_inner(&ast).unwrap_or_else(|err| err.to_compile_error());
    debug_print_generated(&ast, &toks);
    toks.into()
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
