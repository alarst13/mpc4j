package edu.alibaba.mpc4j.s2pc.pcg.ot.cot.sp.ssp;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.PtoFactory;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.s2pc.pcg.dpprf.cdpprf.sp.SpCdpprfFactory;
import edu.alibaba.mpc4j.s2pc.pcg.dpprf.rdpprf.sp.SpRdpprfFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.sp.ssp.gyw23.Gyw23SspCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.sp.ssp.gyw23.Gyw23SspCotReceiver;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.sp.ssp.gyw23.Gyw23SspCotSender;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.sp.ssp.ywl20.*;

/**
 * Single single-point COT factory.
 *
 * @author Weiran Liu
 * @date 2023/3/16
 */
public class SspCotFactory implements PtoFactory {
    /**
     * private constructor.
     */
    private SspCotFactory() {
        // empty
    }

    /**
     * protocol type
     */
    public enum SspCotType {
        /**
         * YWL20 (semi-honest)
         */
        YWL20_SEMI_HONEST,
        /**
         * YWL20 (malicious)
         */
        YWL20_MALICIOUS,
        /**
         * GYW23 (semi-honest)
         */
        GYW23_SEMI_HONEST,
    }

    /**
     * Gets the pre-computed num.
     *
     * @param config the config.
     * @param num    num.
     * @return pre-computed num.
     */
    public static int getPrecomputeNum(SspCotConfig config, int num) {
        MathPreconditions.checkPositive("num", num);
        SspCotType type = config.getPtoType();
        switch (type) {
            case YWL20_SEMI_HONEST:
                Ywl20ShSspCotConfig ywl20ShSspCotConfig = (Ywl20ShSspCotConfig) config;
                return SpRdpprfFactory.getPrecomputeNum(ywl20ShSspCotConfig.getSpDpprfConfig(), num);
            case YWL20_MALICIOUS:
                Ywl20MaSspCotConfig ywl20MaSspCotConfig = (Ywl20MaSspCotConfig) config;
                return SpRdpprfFactory.getPrecomputeNum(ywl20MaSspCotConfig.getSpDpprfConfig(), num) + CommonConstants.BLOCK_BIT_LENGTH;
            case GYW23_SEMI_HONEST:
                Gyw23SspCotConfig gyw23SspCotConfig = (Gyw23SspCotConfig) config;
                return SpCdpprfFactory.getPrecomputeNum(gyw23SspCotConfig.getSpCdpprfConfig(), num);
            default:
                throw new IllegalArgumentException("Invalid " + SspCotType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * Creates a sender.
     *
     * @param senderRpc     sender RPC.
     * @param receiverParty receiver party.
     * @param config        config.
     * @return a sender.
     */
    public static SspCotSender createSender(Rpc senderRpc, Party receiverParty, SspCotConfig config) {
        SspCotType type = config.getPtoType();
        switch (type) {
            case YWL20_SEMI_HONEST:
                return new Ywl20ShSspCotSender(senderRpc, receiverParty, (Ywl20ShSspCotConfig) config);
            case YWL20_MALICIOUS:
                return new Ywl20MaSspCotSender(senderRpc, receiverParty, (Ywl20MaSspCotConfig) config);
            case GYW23_SEMI_HONEST:
                return new Gyw23SspCotSender(senderRpc, receiverParty, (Gyw23SspCotConfig) config);
            default:
                throw new IllegalArgumentException("Invalid " + SspCotType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * Creates a receiver.
     *
     * @param receiverRpc receiver RPC.
     * @param senderParty sender party.
     * @param config      config.
     * @return a receiver.
     */
    public static SspCotReceiver createReceiver(Rpc receiverRpc, Party senderParty, SspCotConfig config) {
        SspCotType type = config.getPtoType();
        switch (type) {
            case YWL20_SEMI_HONEST:
                return new Ywl20ShSspCotReceiver(receiverRpc, senderParty, (Ywl20ShSspCotConfig) config);
            case YWL20_MALICIOUS:
                return new Ywl20MaSspCotReceiver(receiverRpc, senderParty, (Ywl20MaSspCotConfig) config);
            case GYW23_SEMI_HONEST:
                return new Gyw23SspCotReceiver(receiverRpc, senderParty, (Gyw23SspCotConfig) config);
            default:
                throw new IllegalArgumentException("Invalid " + SspCotType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * Creates a default config.
     *
     * @param securityModel the security model.
     * @return a default config.
     */
    public static SspCotConfig createDefaultConfig(SecurityModel securityModel) {
        switch (securityModel) {
            case IDEAL:
            case SEMI_HONEST:
                return new Gyw23SspCotConfig.Builder().build();
            case MALICIOUS:
                return new Ywl20MaSspCotConfig.Builder().build();
            default:
                throw new IllegalArgumentException("Invalid " + SecurityModel.class.getSimpleName() + ": " + securityModel.name());
        }
    }
}
