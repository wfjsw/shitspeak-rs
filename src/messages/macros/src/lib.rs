use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields, Ident, Type};

fn is_vec_u8(ty: &Type) -> bool {
    if let Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            if seg.ident == "Vec" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(Type::Path(inner))) = args.args.first() {
                        if let Some(inner_seg) = inner.path.segments.last() {
                            return inner_seg.ident == "u8";
                        }
                    }
                }
            }
        }
    }
    false
}

#[proc_macro_derive(MessageConversion)]
pub fn message_conversion(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let data = match input.data {
        Data::Enum(data) => data,
        _ => panic!("MessageConversion can only be derived for enums"),
    };

    let mut from_arms = Vec::new();
    let mut proto_tag_arms = Vec::new();
    let mut encoded_len_arms = Vec::new();
    let mut to_proto_arms = Vec::new();
    let mut to_proto_vec_arms = Vec::new();

    for (idx, variant) in data.variants.iter().enumerate() {
        let var_ident = &variant.ident;
        let discr = idx as u16;

        match &variant.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let ty = &fields.unnamed.first().unwrap().ty;
                if is_vec_u8(ty) {
                    // treat as raw bytes
                    from_arms.push(quote! {
                        #discr => Ok(#name::#var_ident(buffer)),
                    });

                    proto_tag_arms.push(quote! {
                        #name::#var_ident(_) => #discr,
                    });

                    encoded_len_arms.push(quote! {
                        #name::#var_ident(data) => data.len(),
                    });

                    to_proto_arms.push(quote! {
                        #name::#var_ident(data) => {
                            buf.put_slice(data);
                            Ok(())
                        },
                    });

                    to_proto_vec_arms.push(quote! {
                        #name::#var_ident(data) => Ok((data.clone())),
                    });
                } else {
                    from_arms.push(quote! {
                        #discr => Ok(#name::#var_ident(<#ty as prost::Message>::decode(&*buffer)?)),
                    });

                    proto_tag_arms.push(quote! {
                        #name::#var_ident(_) => #discr,
                    });

                    encoded_len_arms.push(quote! {
                        #name::#var_ident(msg) => msg.encoded_len(),
                    });

                    to_proto_arms.push(quote! {
                        #name::#var_ident(msg) => {
                            msg.encode(buf)?;
                            Ok(())
                        },
                    });

                    to_proto_vec_arms.push(quote! {
                        #name::#var_ident(msg) => Ok((msg.encode_to_vec())),
                    });
                }
            }
            _ => panic!("Message variants must be single unnamed-field tuple variants"),
        }
    }

    let expanded = quote! {
        impl #name {
            pub fn from_proto(message_type: u16, buffer: Vec<u8>) -> Result<#name, Box<dyn std::error::Error>> {
                match message_type {
                    #(#from_arms)*
                    _ => Err("Unknown message type".into()),
                }
            }

            pub fn proto_tag(&self) -> u16 {
                match self {
                    #(#proto_tag_arms)*
                }
            }

            pub fn encoded_len(&self) -> usize {
                match self {
                    #(#encoded_len_arms)*
                }
            }

            pub fn to_proto(&self, buf: &mut impl bytes::BufMut) -> Result<(), Box<dyn std::error::Error>> {
                match self {
                    #(#to_proto_arms)*
                    _ => Err("Unknown message type".into())
                }
            }

            pub fn to_proto_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                match self {
                    #(#to_proto_vec_arms)*
                }
            }
        }
    };

    TokenStream::from(expanded)
}
