using virgil.crypto;

namespace virgil.crypto {

public class VirgilStreamDataSource : VirgilDataSource
{
    private readonly System.IO.Stream stream;
    private readonly byte[] buffer;

    public VirgilStreamDataSource(System.IO.Stream source)
    {
        this.stream = source;
        this.buffer = new byte[1024];
    }

    public override bool HasData()
    {
        return this.stream.CanRead && this.stream.Position < this.stream.Length;
    }

    public override byte[] Read()
    {
        int bytesRead = this.stream.Read(buffer, 0, buffer.Length);

        if (bytesRead == buffer.Length)
        {
            return buffer;
        }

        byte[] result = new byte[bytesRead];
        System.Array.Copy(buffer, result, bytesRead);
        return result;
    }
}

}
