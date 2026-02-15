#[macro_export]
macro_rules! define_opcodes {
    ($($name:ident = $val:expr),* $(,)?) => {
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum OpCode {
            $($name = $val),*
        }

        impl TryFrom<u8> for OpCode {
            type Error = u8;

            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $($val => Ok(OpCode::$name),)*
                    _ => Err(v),
                }
            }
        }
    };
}