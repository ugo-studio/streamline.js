import { describe, expect, test } from "bun:test";

import { CryptoError, decryptStream, encryptStream } from "../src/lib/crypto";

// Helper to collect stream chunks into a single Uint8Array
async function consumeStream(
    readable: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    const reader = readable.getReader();
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }

    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return result;
}

// Helper to create a ReadableStream from an array of chunks
function createReadableStream(
    chunks: Uint8Array[],
): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(controller) {
            for (const chunk of chunks) {
                controller.enqueue(chunk);
            }
            controller.close();
        },
    });
}

describe("encryptStream and decryptStream", () => {
    const secretKey = "a-very-secret-key-for-streaming";
    const plaintextChunks = [
        new TextEncoder().encode("This is the first chunk."),
        new TextEncoder().encode(
            "This is the second chunk, which is a bit longer.",
        ),
        new TextEncoder().encode("And a final one."),
    ];

    const fullPlaintext = new Uint8Array(
        plaintextChunks.reduce((acc, c) => acc + c.length, 0),
    );
    let offset = 0;
    for (const chunk of plaintextChunks) {
        fullPlaintext.set(chunk, offset);
        offset += chunk.length;
    }

    test("should encrypt and decrypt a stream successfully", async () => {
        const sourceStream = createReadableStream(plaintextChunks);

        const encryptor = encryptStream(secretKey);
        const decryptor = decryptStream(secretKey);

        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const decryptedStream = encryptedStream.pipeThrough(decryptor);

        const result = await consumeStream(decryptedStream);

        expect(result).toEqual(fullPlaintext);
    });

    test("should fail decryption with a wrong secret key", async () => {
        const sourceStream = createReadableStream(plaintextChunks);
        const encryptor = encryptStream(secretKey);
        const encryptedStream = sourceStream.pipeThrough(encryptor);

        // Now, try to decrypt with the wrong key
        const wrongKey = "this-is-not-the-key";
        const decryptor = decryptStream(wrongKey);
        const decryptedStream = encryptedStream.pipeThrough(decryptor);

        // Expect the consumption of the stream to throw a decryption error
        const promise = consumeStream(decryptedStream);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "DECRYPTION_FAILED",
        );
    });

    test("should fail if the stream is truncated (missing frames)", async () => {
        const sourceStream = createReadableStream(plaintextChunks);
        const encryptor = encryptStream(secretKey);
        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const encryptedBytes = await consumeStream(encryptedStream);

        // Truncate the stream (remove the last 10 bytes)
        const truncatedBytes = encryptedBytes.subarray(
            0,
            encryptedBytes.length - 10,
        );
        const truncatedStream = createReadableStream([truncatedBytes]);

        const decryptor = decryptStream(secretKey);
        const decryptedStream = truncatedStream.pipeThrough(decryptor);

        const promise = consumeStream(decryptedStream);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "INVALID_DATA",
        );
    });

    test("should fail if a frame is tampered with", async () => {
        const sourceStream = createReadableStream(plaintextChunks);
        const encryptor = encryptStream(secretKey);
        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const encryptedBytes = await consumeStream(encryptedStream);

        // Tamper with a byte in the middle of the ciphertext
        if (encryptedBytes.length > 100) {
            encryptedBytes[100] ^= 0xff; // Flip a bit
        }

        const tamperedStream = createReadableStream([encryptedBytes]);
        const decryptor = decryptStream(secretKey);
        const decryptedStream = tamperedStream.pipeThrough(decryptor);

        const promise = consumeStream(decryptedStream);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "INVALID_DATA",
        );
    });

    test("should respect TTL and fail if expired", async () => {
        const sourceStream = createReadableStream(plaintextChunks);
        const encryptor = encryptStream(secretKey, { ttl: 200 }); // 200ms TTL
        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const encryptedBytes = await consumeStream(encryptedStream);

        // Wait for TTL to expire
        await new Promise((resolve) => setTimeout(resolve, 250));

        const expiredStream = createReadableStream([encryptedBytes]);
        const decryptor = decryptStream(secretKey);
        const decryptedStream = expiredStream.pipeThrough(decryptor);

        const promise = consumeStream(decryptedStream);
        await expect(promise).rejects.toThrow(CryptoError);
        await expect(promise).rejects.toHaveProperty(
            "code",
            "EXPIRED",
        );
    });

    test("should handle empty input stream", async () => {
        const sourceStream = createReadableStream([]);
        const encryptor = encryptStream(secretKey);
        const decryptor = decryptStream(secretKey);

        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const decryptedStream = encryptedStream.pipeThrough(decryptor);

        const result = await consumeStream(decryptedStream);
        expect(result.length).toBe(0);
    });

    test("should handle single-chunk stream", async () => {
        const singleChunk = new TextEncoder().encode("A single chunk of data.");
        const sourceStream = createReadableStream([singleChunk]);

        const encryptor = encryptStream(secretKey);
        const decryptor = decryptStream(secretKey);

        const encryptedStream = sourceStream.pipeThrough(encryptor);
        const decryptedStream = encryptedStream.pipeThrough(decryptor);

        const result = await consumeStream(decryptedStream);
        expect(result).toEqual(singleChunk);
    });
});
