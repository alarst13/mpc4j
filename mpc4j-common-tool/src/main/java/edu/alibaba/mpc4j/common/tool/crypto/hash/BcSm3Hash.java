package edu.alibaba.mpc4j.common.tool.crypto.hash;

import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory.HashType;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;
import org.bouncycastle.jcajce.provider.digest.SM3;

import java.util.Arrays;

/**
 * 应用Bouncy Castle哈希引擎实现的SM3哈希函数。
 *
 * @author Weiran Liu
 * @date 2021/12/04
 */
class BcSm3Hash implements Hash {
    /**
     * 单位输出长度
     */
    static final int DIGEST_BYTE_LENGTH = 32;
    /**
     * 输出字节长度
     */
    private final int outputByteLength;

    BcSm3Hash(int outputByteLength) {
        assert outputByteLength > 0 && outputByteLength <= DIGEST_BYTE_LENGTH
            : "Output byte length must be in range (0, " + DIGEST_BYTE_LENGTH + "]";
        this.outputByteLength = outputByteLength;
    }

    @Override
    public byte[] digestToBytes(byte[] message) {
        assert message.length > 0 : "Message length must be greater than 0: " + message.length;
        // 哈希函数不是线程安全的，因此每调用一次都需要创建一个新的哈希函数实例，保证线程安全性
        BCMessageDigest messageDigest = new SM3.Digest();
        if (outputByteLength == DIGEST_BYTE_LENGTH) {
            // 如果输出字节长度等于哈希函数单位输出长度，则只调用一次哈希函数，且可以减少一次内存拷贝
            return messageDigest.digest(message);
        } else {
            // 如果输出字节长度小于等于哈希函数单位输出长度，则只调用一次哈希函数，截断输出
            byte[] output = messageDigest.digest(message);
            return Arrays.copyOf(output, outputByteLength);
        }
    }

    @Override
    public int getOutputByteLength() {
        return outputByteLength;
    }

    @Override
    public HashType getHashType() {
        return HashType.BC_SM3;
    }
}
