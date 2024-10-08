package edu.alibaba.mpc4j.s2pc.aby.operator.agg.max.zl;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyMemoryRpcPto;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.galoisfield.zl.Zl;
import edu.alibaba.mpc4j.common.tool.galoisfield.zl.ZlFactory;
import edu.alibaba.mpc4j.common.structure.vector.ZlVector;
import edu.alibaba.mpc4j.s2pc.aby.basics.z2.Z2cConfig;
import edu.alibaba.mpc4j.s2pc.aby.basics.z2.Z2cFactory;
import edu.alibaba.mpc4j.s2pc.aby.basics.z2.Z2cParty;
import edu.alibaba.mpc4j.s2pc.aby.basics.zl.SquareZlVector;
import edu.alibaba.mpc4j.s2pc.aby.operator.agg.max.zl.rrk20.Rrk20ZlMaxConfig;
import org.apache.commons.lang3.time.StopWatch;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/**
 * Zl Max Test.
 *
 * @author Li Peng
 * @date 2023/5/24
 */
@RunWith(Parameterized.class)
public class ZlMaxTest extends AbstractTwoPartyMemoryRpcPto {
    private static final Logger LOGGER = LoggerFactory.getLogger(ZlMaxTest.class);
    /**
     * default num
     */
    private static final int DEFAULT_NUM = 1000;
    /**
     * large num
     */
    private static final int LARGE_NUM = 1 << 14;

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> configurations() {
        Collection<Object[]> configurations = new ArrayList<>();

        // RRK+20
        configurations.add(new Object[]{
                ZlMaxFactory.ZlMaxType.RRK20.name(),
            new Rrk20ZlMaxConfig.Builder(SecurityModel.SEMI_HONEST, true).build()
        });

        return configurations;
    }

    /**
     * the config
     */
    private final ZlMaxConfig config;
    /**
     * Zl
     */
    private final Zl zl;

    public ZlMaxTest(String name, ZlMaxConfig config) {
        super(name);
        this.config = config;
        this.zl = ZlFactory.createInstance(EnvType.STANDARD, Long.SIZE);
    }

    @Test
    public void test1Num() {
        testPto(1, false);
    }

    @Test
    public void test2Num() {
        testPto(2, false);
    }

    @Test
    public void test8Num() {
        testPto(8, false);
    }

    @Test
    public void test7Num() {
        testPto(7, false);
    }

    @Test
    public void test9Num() {
        testPto(9, false);
    }

    @Test
    public void test19Num() {
        testPto(19, false);
    }

    @Test
    public void testDefaultNum() {
        testPto(DEFAULT_NUM, false);
    }

    @Test
    public void testParallelDefaultNum() {
        testPto(DEFAULT_NUM, true);
    }

    @Test
    public void testLargeNum() {
        testPto(LARGE_NUM, false);
    }

    @Test
    public void testParallelLargeNum() {
        testPto(LARGE_NUM, true);
    }

    private void testPto(int num, boolean parallel) {
        // make sure bit length of zl > 2
        Assert.assertTrue(zl.getL() > 2);
        // create inputs, making sure that the plain value is positive under 2' complement notation in zl.
        BigInteger[] randomsX0 = IntStream.range(0, num)
                .mapToObj(i -> new BigInteger(zl.getL() - 2, SECURE_RANDOM)).toArray(BigInteger[]::new);
        BigInteger[] randomsX1 = IntStream.range(0, num)
                .mapToObj(i -> new BigInteger(zl.getL() - 2, SECURE_RANDOM)).toArray(BigInteger[]::new);
        ZlVector x0 = ZlVector.create(zl, randomsX0);
        ZlVector x1 = ZlVector.create(zl, randomsX1);
        SquareZlVector shareX0 = SquareZlVector.create(x0, false);
        SquareZlVector shareX1 = SquareZlVector.create(x1, false);
        // init z2c
        Z2cConfig z2cConfig = Z2cFactory.createDefaultConfig(SecurityModel.SEMI_HONEST, true);
        Z2cParty z2cSender = Z2cFactory.createSender(firstRpc, secondRpc.ownParty(), z2cConfig);
        Z2cParty z2cReceiver = Z2cFactory.createReceiver(secondRpc, firstRpc.ownParty(), z2cConfig);
        // init the protocol
        ZlMaxParty sender = ZlMaxFactory.createSender(z2cSender, secondRpc.ownParty(), config);
        ZlMaxParty receiver = ZlMaxFactory.createReceiver(z2cReceiver, firstRpc.ownParty(), config);
        sender.setParallel(parallel);
        receiver.setParallel(parallel);
        try {
            LOGGER.info("-----test {} start-----", sender.getPtoDesc().getPtoName());
            ZlMaxPartyThread senderThread = new ZlMaxPartyThread(sender, z2cSender, zl, shareX0);
            ZlMaxPartyThread receiverThread = new ZlMaxPartyThread(receiver, z2cReceiver, zl, shareX1);
            StopWatch stopWatch = new StopWatch();
            // execute the protocol
            stopWatch.start();
            senderThread.start();
            receiverThread.start();
            senderThread.join();
            receiverThread.join();
            stopWatch.stop();
            long time = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            // verify
            SquareZlVector shareZ0 = senderThread.getShareZ();
            SquareZlVector shareZ1 = receiverThread.getShareZ();
            assertOutput(x0, x1, shareZ0, shareZ1);
            printAndResetRpc(time);
            LOGGER.info("-----test {} end-----", sender.getPtoDesc().getPtoName());
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // destroy
        new Thread(sender::destroy).start();
        new Thread(receiver::destroy).start();
    }

    private void assertOutput(ZlVector x0, ZlVector x1, SquareZlVector shareZ0, SquareZlVector shareZ1) {
        Assert.assertEquals(1, shareZ0.getNum());
        Assert.assertEquals(1, shareZ1.getNum());
        List<BigInteger> xElements = Arrays.asList(x0.add(x1).getElements());
        BigInteger z = shareZ0.getZlVector().add(shareZ1.getZlVector()).getElement(0);
        Collections.sort(xElements);
        Assert.assertEquals(z, xElements.get(xElements.size() - 1));
    }
}
