using virgil.crypto;

namespace virgil.crypto {

public class VirgilStreamDataSink : VirgilDataSink
{
    private readonly System.IO.Stream stream;

    public VirgilStreamDataSink(System.IO.Stream target)
    {
        this.stream = target;
    }

    public override bool IsGood()
    {
        return this.stream.CanWrite;
    }

    public override void Write(byte[] data)
    {
        this.stream.Write(data, 0, data.Length);
    }
}

}
