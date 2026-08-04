//! 双向转发。第一版用 `copy_bidirectional` 满足正确性与缓冲复用；
//! 热路径的自定义缓冲/零拷贝（splice）留待第二阶段。

use tokio::io::{ AsyncRead, AsyncWrite, copy_bidirectional };

use crate::error::Result;

/// 在两条流之间双向搬数据，任一方向 EOF/出错即结束并关闭两端。
pub async fn relay<A, B>(mut a: A, mut b: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(&mut a, &mut b).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt, duplex };

    #[tokio::test]
    async fn relays_both_directions() {
        let (a_ext, a_int) = duplex(64);
        let (b_ext, b_int) = duplex(64);
        tokio::spawn(async move {
            let _ = relay(a_int, b_int).await;
        });

        let (mut a_ext, mut b_ext) = (a_ext, b_ext);
        a_ext.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        b_ext.write_all(b"pong").await.unwrap();
        a_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// 一端关闭后转发应当结束，而不是挂住。
    #[tokio::test]
    async fn finishes_when_one_side_closes() {
        let (mut a_ext, a_int) = duplex(64);
        let (mut b_ext, b_int) = duplex(64);
        let task = tokio::spawn(async move { relay(a_int, b_int).await });

        a_ext.write_all(b"bye").await.unwrap();
        a_ext.shutdown().await.unwrap();
        drop(a_ext);

        let mut got = Vec::new();
        b_ext.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bye");

        drop(b_ext);
        task.await.unwrap().unwrap();
    }
}
