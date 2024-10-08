package edu.alibaba.mpc4j.s2pc.pcg.ot.lnot.nc;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.PtoFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.lnot.nc.cot.CotNcLnotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.lnot.nc.cot.CotNcLnotReceiver;
import edu.alibaba.mpc4j.s2pc.pcg.ot.lnot.nc.cot.CotNcLnotSender;

/**
 * no-choice 1-out-of-n (with n = 2^l) factory.
 *
 * @author Weiran Liu
 * @date 2023/4/11
 */
public class NcLnotFactory implements PtoFactory {
    /**
     * private constructor.
     */
    private NcLnotFactory() {
        // empty
    }

    /**
     * the type.
     */
    public enum NcLnotType {
        /**
         * COT
         */
        COT,
    }

    /**
     * Creates a sender.
     *
     * @param senderRpc     the sender RPC.
     * @param receiverParty the receiver party.
     * @param config        the config.
     * @return a sender.
     */
    public static NcLnotSender createSender(Rpc senderRpc, Party receiverParty, NcLnotConfig config) {
        NcLnotType type = config.getPtoType();
        //noinspection SwitchStatementWithTooFewBranches
        switch (type) {
            case COT:
                return new CotNcLnotSender(senderRpc, receiverParty, (CotNcLnotConfig) config);
            default:
                throw new IllegalArgumentException("Invalid " + NcLnotType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * Creates a receiver.
     *
     * @param receiverRpc the receiver RPC.
     * @param senderParty the sender party.
     * @param config      the config.
     * @return a receiver.
     */
    public static NcLnotReceiver createReceiver(Rpc receiverRpc, Party senderParty, NcLnotConfig config) {
        NcLnotType type = config.getPtoType();
        //noinspection SwitchStatementWithTooFewBranches
        switch (type) {
            case COT:
                return new CotNcLnotReceiver(receiverRpc, senderParty, (CotNcLnotConfig) config);
            default:
                throw new IllegalArgumentException("Invalid " + NcLnotType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * Creates a default config.
     *
     * @param securityModel the security model.
     * @return a default config.
     */
    public static NcLnotConfig createDefaultConfig(SecurityModel securityModel) {
        return new CotNcLnotConfig.Builder(securityModel).build();
    }
}
