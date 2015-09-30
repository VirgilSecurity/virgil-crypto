package com.virgilsecurity.crypto;

public class VirgilStreamDataSink extends VirgilDataSink implements java.io.Closeable {
    private java.io.OutputStream stream;

    public VirgilStreamDataSink(java.io.OutputStream stream) {
        this.stream = stream;
    }

    @Override
    public boolean isGood() throws java.io.IOException {
        // If stream is not good, method 'write' will throw exception.
        return true;
    }

    @Override
    public void write(byte[] data) throws java.io.IOException {
        this.stream.write(data, 0, data.length);
    }

    @Override
    public void close() throws java.io.IOException {
        this.stream.close();
        this.delete();
    }
}
