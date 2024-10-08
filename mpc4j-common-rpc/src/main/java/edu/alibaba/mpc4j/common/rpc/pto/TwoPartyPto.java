package edu.alibaba.mpc4j.common.rpc.pto;

import edu.alibaba.mpc4j.common.rpc.Party;

/**
 * Two-party protocol interface.
 *
 * @author Weiran Liu
 * @date 2021/12/19
 */
public interface TwoPartyPto extends MultiPartyPto {
    /**
     * Gets other party.
     *
     * @return other party.
     */
    default Party otherParty() {
        return otherParties()[0];
    }
}
