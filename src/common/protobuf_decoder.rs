//! Protobuf payload validation; connection framing belongs to the transport.

use prost::Message;

/// 安全的 protobuf 消息内容解码函数
///
/// 此函数安全地尝试解码 protobuf 数据，如果解码失败则返回错误而不是崩溃
pub fn safe_protobuf_decode<T>(data: &[u8]) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
where
    T: Message + Default,
{
    match T::decode(data) {
        Ok(message) => Ok(message),
        Err(e) => Err(Box::new(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, PartialEq, Message)]
    struct TestMessage {
        #[prost(string, tag = "1")]
        content: String,
        #[prost(int32, tag = "2")]
        id: i32,
    }

    #[test]
    fn test_safe_protobuf_decode() {
        let test_msg = TestMessage {
            content: "Safe decode test".to_string(),
            id: 999,
        };

        let encoded = test_msg.encode_to_vec();
        let decoded = safe_protobuf_decode::<TestMessage>(&encoded).unwrap();

        assert_eq!(decoded.content, "Safe decode test");
        assert_eq!(decoded.id, 999);
        assert!(safe_protobuf_decode::<TestMessage>(&[0xff]).is_err());
    }
}
