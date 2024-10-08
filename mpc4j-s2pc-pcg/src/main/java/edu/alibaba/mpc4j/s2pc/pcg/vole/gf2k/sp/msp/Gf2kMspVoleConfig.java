package edu.alibaba.mpc4j.s2pc.pcg.vole.gf2k.sp.msp;

import edu.alibaba.mpc4j.common.rpc.pto.MultiPartyPtoConfig;
import edu.alibaba.mpc4j.s2pc.pcg.vole.gf2k.sp.bsp.Gf2kBspVoleConfig;
import edu.alibaba.mpc4j.s2pc.pcg.vole.gf2k.sp.msp.Gf2kMspVoleFactory.Gf2kMspVoleType;

/**
 * multi single-point GF2K-VOLE config.
 *
 * @author Weiran Liu
 * @date 2023/7/22
 */
public interface Gf2kMspVoleConfig extends MultiPartyPtoConfig {
    /**
     * Gets the protocol type.
     *
     * @return the protocol type.
     */
    Gf2kMspVoleType getPtoType();

    /**
     * Gets batched single-point GF2K-VOLE config.
     *
     * @return batched single-point GF2K-VOLE config.
     */
    Gf2kBspVoleConfig getGf2kBspVoleConfig();
}
