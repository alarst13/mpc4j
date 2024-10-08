package edu.alibaba.mpc4j.common.rpc.desc;

/**
 * Security model.
 *
 * @author Weiran Liu
 * @date 2021/12/09
 */
public enum SecurityModel {
    /**
     * ideal world, no security.
     */
    IDEAL,
    /**
     * trusted dealer
     */
    TRUSTED_DEALER,
    /**
     * semi-honest security.
     */
    SEMI_HONEST,
    /**
     * malicious security.
     */
    MALICIOUS,
}
