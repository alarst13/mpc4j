package edu.alibaba.mpc4j.common.tool.network.twaksman;

import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkFactory;
import edu.alibaba.mpc4j.common.tool.network.PermutationNetworkFactory.PermutationNetworkType;
import edu.alibaba.mpc4j.common.tool.utils.LongUtils;

import java.util.Arrays;
import java.util.Stack;
import java.util.concurrent.ForkJoinTask;
import java.util.stream.IntStream;

/**
 * Waksman network but assign values according to the highest bit
 *
 * @author Feng Han
 * @date 2024/6/14
 */
public class TopWaksmanNetwork<T> extends AbstractTopWaksmanNetwork<T> {

    /**
     * Creates a network.
     *
     * @param permutationMap permutation map.
     */
    public TopWaksmanNetwork(final int[] permutationMap) {
        super(permutationMap);
        // iteratively create the Benes network
        genWaksmanRoute(permutationMap);
        // update widths
        updateWidths();
    }

    /**
     * Creates a network by directly setting the network.
     *
     * @param n       number of inputs.
     * @param network network.
     */
    public TopWaksmanNetwork(final int n, final byte[][] network) {
        super(n, network);
    }

    private void genWaksmanRoute(final int[] permutationMap) {
        int logN = LongUtils.ceilLog2(n);
        genWaksmanRoute(logN, 0, 0, permutationMap);
    }

    private void genWaksmanRoute(int subLogN, int levelIndex, int permIndex, int[] perms) {
        int subN = perms.length;
        if (subN == 2) {
            assert (subLogN == 1 || subLogN == 2);
            if (subLogN == 1) {
                genSingleLevel(levelIndex, permIndex, perms);
            } else {
                genPadSingleLevel(levelIndex, permIndex, perms);
            }
        } else if (subN == 3) {
            assert subLogN == 2;
            genTripleLevel(levelIndex, permIndex, perms);
        } else if (subN == 4) {
            assert (subLogN == 2 || subLogN == 3);
            if (subLogN == 2) {
                genQuadrupleLevel(levelIndex, permIndex, perms);
            } else {
                genPadQuadrupleLevel(levelIndex, permIndex, perms);
            }
        } else {
            int subLevel = 2 * subLogN - 1;
            // top subnetwork map, with size Math.floor(n / 2)
            int subTopN = subN / 2;
            // bottom subnetwork map, with size Math.ceil(n / 2)
            int subBottomN = subN - subTopN;
            // create forward/backward lookup tables
            int[] invPerms = new int[subN];
            IntStream.range(0, subN).forEach(i -> invPerms[perms[i]] = i);
            // path, initialized by -1, we use 2 for empty node
            int[] path = new int[subN];
            Arrays.fill(path, -1);
            if (subN % 2 == 1) {
                // handling odd n, the last node directly links to the bottom subnetwork.
                path[subN - 1] = 1;
                path[perms[subN - 1]] = 1;
                // if values - 1 == perm[values - 1], then the last one is also a direct link. Handle other cases.
                if (perms[subN - 1] != subN - 1) {
                    int idx = perms[getNeighbor(invPerms[subN - 1], subTopN)];
                    depthFirstSearch(path, perms, invPerms, idx, subTopN);
                }
            } else {
                // handling even n
                evenDepthFirstSearch(path, perms, invPerms, subTopN);
            }
            // set other switches
            for (int i = 0; i < subN; ++i) {
                if (path[i] < 0) {
                    depthFirstSearch(path, perms, invPerms, i, subTopN);
                }
            }
            // create the subnetworks.
            int[] subTopDests = new int[subTopN];
            int[] subBottomDests = new int[subBottomN];
            byte[] leftNet = network[levelIndex];
            byte[] rightNet = network[levelIndex + subLevel - 1];

            for (int halfIndex = 0; halfIndex < subTopN; halfIndex++) {
                leftNet[permIndex + halfIndex] = (byte) path[halfIndex];
                // 对应的index是不是来自于上半个网络
                int rightFromTop = path[perms[halfIndex]];
                rightNet[permIndex + halfIndex] = (byte) rightFromTop;
                if (rightFromTop == 0) {
                    subTopDests[halfIndex] = subHalf(perms[halfIndex], subTopN);
                    subBottomDests[halfIndex] = subHalf(perms[getNeighbor(halfIndex, subTopN)], subTopN);
                } else {
                    subBottomDests[halfIndex] = subHalf(perms[halfIndex], subTopN);
                    subTopDests[halfIndex] = subHalf(perms[getNeighbor(halfIndex, subTopN)], subTopN);
                }
            }
            if (subN % 2 == 1) {
                // add one more switch for the odd case.
                subBottomDests[subN / 2] = subHalf(perms[subN - 1], subTopN);
            } else {
                // remove one switch for the even case.
                network[levelIndex + subLevel - 1][permIndex + subN / 2 - 1] = 2;
            }

            if (parallel && n > PermutationNetworkFactory.PARALLEL_THRESHOLD && forkJoinPool.getParallelism() - forkJoinPool.getActiveThreadCount() > 0) {
                ForkJoinTask<?> topTask = forkJoinPool.submit(() ->
                    genWaksmanRoute(subLogN - 1, levelIndex + 1, permIndex, subTopDests));
                ForkJoinTask<?> subTask = forkJoinPool.submit(() ->
                    genWaksmanRoute(subLogN - 1, levelIndex + 1, permIndex + subN / 4, subBottomDests)
                );
                topTask.join();
                subTask.join();
            } else {
                // create top subnetwork, with (log(N) - 1) levels
                genWaksmanRoute(subLogN - 1, levelIndex + 1, permIndex, subTopDests);
                // create bottom subnetwork with (log(N) - 1) levels.
                genWaksmanRoute(subLogN - 1, levelIndex + 1, permIndex + subN / 4, subBottomDests);
            }
        }
    }

    private void genSingleLevel(int levelIndex, int permIndex, int[] subDests) {
        // logN == 1, we have 2 * log(N) - 1 = 1 level (█)
        network[levelIndex][permIndex] = subDests[0] == 0 ? (byte) 0 : (byte) 1;
    }

    private void genPadSingleLevel(int levelIndex, int permIndex, int[] subDests) {
        // logN == 2，we have 2 * logN - 1 = 3 levels (□ █ □).
        network[levelIndex][permIndex] = 2;
        network[levelIndex + 1][permIndex] = subDests[0] == 0 ? (byte) 0 : (byte) 1;
        network[levelIndex + 2][permIndex] = 2;
    }

    private void genTripleLevel(int levelIndex, int permIndex, int[] subDests) {
        if (subDests[0] == 0) {
            /*
             * [0, 1, 2] -> [0, 1, 2], █ □ █ = 0   0
             *                         □ █ □     0
             *
             * [0, 1, 2] -> [0, 2, 1], █ □ █ = 0   0
             *                         □ █ □     1
             */
            network[levelIndex][permIndex] = 0;
            network[levelIndex + 1][permIndex] = subDests[1] == 1 ? (byte) 0 : (byte) 1;
            network[levelIndex + 2][permIndex] = 0;
        } else if (subDests[1] == 0) {
            /*
             * [0, 1, 2] -> [1, 0, 2], █ □ █ = 0   1
             *                         □ █ □     0
             *
             * [0, 1, 2] -> [1, 2, 0], █ □ █ = 0   1
             *                         □ █ □     1
             */
            network[levelIndex][permIndex] = 0;
            network[levelIndex + 1][permIndex] = subDests[0] == 1 ? (byte) 0 : (byte) 1;
            network[levelIndex + 2][permIndex] = 1;
        } else {
            /*
             * [0, 1, 2] -> [2, 0, 1], █ □ █ = 1   0
             *                         □ █ □     1
             *
             * [0, 1, 2] -> [2, 1, 0], █ □ █ = 1   1
             *                         □ █ □     1
             */
            network[levelIndex][permIndex] = 1;
            network[levelIndex + 1][permIndex] = 1;
            network[levelIndex + 2][permIndex] = subDests[0] == 1 ? (byte) 0 : (byte) 1;
        }
    }

    private void genQuadrupleLevel(int levelIndex, int permIndex, int[] subDests) {
        byte[] switches = genQuadrupleSwitches(subDests);
        network[levelIndex][permIndex] = switches[0];
        network[levelIndex][permIndex + 1] = switches[1];
        network[levelIndex + 1][permIndex] = switches[2];
        network[levelIndex + 1][permIndex + 1] = switches[3];
        network[levelIndex + 2][permIndex] = switches[4];
        network[levelIndex + 2][permIndex + 1] = 2;
    }

    private void genPadQuadrupleLevel(int levelIndex, int permIndex, int[] subDests) {
        byte[] switches = genQuadrupleSwitches(subDests);
        network[levelIndex][permIndex] = switches[0];
        network[levelIndex][permIndex + 1] = switches[1];
        network[levelIndex + 1][permIndex] = 2;
        network[levelIndex + 1][permIndex + 1] = 2;
        network[levelIndex + 2][permIndex] = switches[2];
        network[levelIndex + 2][permIndex + 1] = switches[3];
        network[levelIndex + 3][permIndex] = 2;
        network[levelIndex + 3][permIndex + 1] = 2;
        network[levelIndex + 4][permIndex] = switches[4];
        network[levelIndex + 4][permIndex + 1] = 2;
    }

    private byte[] genQuadrupleSwitches(int[] subDests) {
        assert subDests.length == 4;
        if (subDests[0] == 0) {
            // [0, 1, 2, 3] -> [0, ?, ?, ?]
            if (subDests[1] == 1) {
                // [0, 1, 2, 3] -> [0, 1, ?, ?]
                if (subDests[2] == 2) {
                    /*
                     * [0, 1, 2, 3] -> [0, 1, 2, 3], █ █ █ = 0 0 0
                     *                               █ █ □   0 0
                     */
                    return new byte[]{0, 0, 0, 0, 0};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [0, 1, 3, 2], █ █ █ = 0 0 0
                     *                               █ █ □   0 1
                     */
                    return new byte[]{0, 0, 0, 1, 0};
                }
            } else if (subDests[1] == 2) {
                // [0, 1, 2, 3] -> [0, 2, ?, ?]
                if (subDests[2] == 1) {
                    /*
                     * [0, 1, 2, 3] -> [0, 2, 1, 3], █ █ █ = 1 1 1
                     *                               █ █ □   0 0
                     */
                    return new byte[]{1, 0, 1, 0, 1};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [0, 2, 3, 1], █ █ █ = 1 1 1
                     *                               █ █ □   1 0
                     */
                    return new byte[]{1, 1, 1, 0, 1};
                }
            } else {
                assert subDests[1] == 3;
                // [0, 1, 2, 3] -> [0, 3, ?, ?]
                if (subDests[2] == 1) {
                    /*
                     * [0, 1, 2, 3] -> [0, 3, 1, 2], █ █ █ = 0 0 0
                     *                               █ █ □   1 1
                     */
                    return new byte[]{0, 1, 0, 1, 0};
                } else {
                    assert subDests[2] == 2;
                    /*
                     * [0, 1, 2, 3] -> [0, 3, 2, 1], █ █ █ = 0 0 0
                     *                               █ █ □   1 0
                     */
                    return new byte[]{0, 1, 0, 0, 0};
                }
            }
        } else if (subDests[0] == 1) {
            // [0, 1, 2, 3] -> [1, ?, ?, ?]
            if (subDests[1] == 0) {
                // [0, 1, 2, 3] -> [1, 0, ?, ?]
                if (subDests[2] == 2) {
                    /*
                     * [0, 1, 2, 3] -> [1, 0, 2, 3], █ █ █ = 0 1 0
                     *                               █ █ □   0 0
                     */
                    return new byte[]{0, 0, 1, 0, 0};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [1, 0, 3, 2], █ █ █ = 0 1 0
                     *                               █ █ □   0 1
                     */
                    return new byte[]{0, 0, 1, 1, 0};
                }
            } else if (subDests[1] == 2) {
                // [0, 1, 2, 3] -> [1, 2, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [1, 2, 0, 3], █ █ █ = 1 1 0
                     *                               █ █ □   0 0
                     */
                    return new byte[]{1, 0, 1, 0, 0};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [1, 2, 3, 0], █ █ █ = 1 1 0
                     *                               █ █ □   0 1
                     */
                    return new byte[]{1, 0, 1, 1, 0};
                }
            } else {
                assert subDests[1] == 3;
                // [0, 1, 2, 3] -> [1, 3, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [1, 3, 0, 2], █ █ █ = 0 0 1
                     *                               █ █ □   1 1
                     */
                    return new byte[]{0, 1, 0, 1, 1};
                } else {
                    assert subDests[2] == 2;
                    /*
                     * [0, 1, 2, 3] -> [1, 3, 2, 0], █ █ █ = 1 0 1
                     *                               █ █ □   1 1
                     */
                    return new byte[]{1, 1, 0, 1, 1};
                }
            }
        } else if (subDests[0] == 2) {
            // [0, 1, 2, 3] -> [2, ?, ?, ?]
            if (subDests[1] == 0) {
                // [0, 1, 2, 3] -> [2, 0, ?, ?]
                if (subDests[2] == 1) {
                    /*
                     * [0, 1, 2, 3] -> [2, 0, 1, 3], █ █ █ = 0 1 1
                     *                               █ █ □   0 0
                     */
                    return new byte[]{0, 0, 1, 0, 1};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [2, 0, 3, 1], █ █ █ = 0 1 1
                     *                               █ █ □   1 0
                     */
                    return new byte[]{0, 1, 1, 0, 1};
                }
            } else if (subDests[1] == 1) {
                // [0, 1, 2, 3] -> [2, 1, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [2, 1, 0, 3], █ █ █ = 1 0 0
                     *                               █ █ □   0 0
                     */
                    return new byte[]{1, 0, 0, 0, 0};
                } else {
                    assert subDests[2] == 3;
                    /*
                     * [0, 1, 2, 3] -> [2, 1, 3, 0], █ █ █ = 1 0 0
                     *                               █ █ □   0 1
                     */
                    return new byte[]{1, 0, 0, 1, 0};
                }
            } else {
                assert subDests[1] == 3;
                // [0, 1, 2, 3] -> [2, 3, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [2, 3, 0, 1], █ █ █ = 1 0 0
                     *                               █ █ □   1 0
                     */
                    return new byte[]{1, 1, 0, 0, 0};
                } else {
                    assert subDests[2] == 1;
                    /*
                     * [0, 1, 2, 3] -> [2, 3, 1, 0], █ █ █ = 1 0 0
                     *                               █ █ □   1 1
                     */
                    return new byte[]{1, 1, 0, 1, 0};
                }
            }
        } else {
            assert subDests[0] == 3;
            // [0, 1, 2, 3] -> [3, ?, ?, ?]
            if (subDests[1] == 0) {
                // [0, 1, 2, 3] -> [3, 0, ?, ?]
                if (subDests[2] == 1) {
                    /*
                     * [0, 1, 2, 3] -> [3, 0, 1, 2], █ █ █ = 0 1 1
                     *                               █ █ □   0 1
                     */
                    return new byte[]{0, 0, 1, 1, 1};
                } else {
                    assert subDests[2] == 2;
                    /*
                     * [0, 1, 2, 3] -> [3, 0, 2, 1], █ █ █ = 0 1 0
                     *                               █ █ □   1 0
                     */
                    return new byte[]{0, 1, 1, 0, 0};
                }
            } else if (subDests[1] == 1) {
                // [0, 1, 2, 3] -> [3, 1, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [3, 1, 0, 2], █ █ █ = 0 0 1
                     *                               █ █ □   0 1
                     */
                    return new byte[]{0, 0, 0, 1, 1};
                } else {
                    assert subDests[2] == 2;
                    /*
                     * [0, 1, 2, 3] -> [3, 1, 2, 0], █ █ █ = 1 0 1
                     *                               █ █ □   0 1
                     */
                    return new byte[]{1, 0, 0, 1, 1};
                }
            } else {
                assert subDests[1] == 2;
                // [0, 1, 2, 3] -> [3, 2, ?, ?]
                if (subDests[2] == 0) {
                    /*
                     * [0, 1, 2, 3] -> [3, 2, 0, 1], █ █ █ = 1 1 0
                     *                               █ █ □   1 0
                     */
                    return new byte[]{1, 1, 1, 0, 0};
                } else {
                    assert subDests[2] == 1;
                    /*
                     * [0, 1, 2, 3] -> [3, 2, 1, 0], █ █ █ = 1 1 0
                     *                               █ █ □   1 1
                     */
                    return new byte[]{1, 1, 1, 1, 0};
                }
            }
        }
    }

    private void depthFirstSearch(int[] path, int[] perms, int[] invPerms, int idx, int step) {
        Stack<int[]> stack = new Stack<>();
        stack.push(new int[]{idx, 0});
        while (!stack.empty()) {
            int[] pair = stack.pop();
            path[pair[0]] = pair[1];
            // if the next item in the vertical array is unassigned
            int target = getNeighbor(pair[0], step);
            if (path[target] < 0) {
                // the next item is always assigned the opposite of this item,
                // unless it was part of path/cycle of previous node
                stack.push(new int[]{target, pair[1] ^ 1});
            }
            idx = perms[getNeighbor(invPerms[pair[0]], step)];
            if (path[idx] < 0) {
                stack.push(new int[]{idx, pair[1] ^ 1});
            }
        }
    }

    private void evenDepthFirstSearch(int[] path, int[] perms, int[] invPerms, int step) {
        assert path.length > 4 && path.length % 2 == 0;
        // set the last path to be 0
        int idx = perms[path.length - 1];
        Stack<int[]> stack = new Stack<>();
        stack.push(new int[]{idx, 1});
        while (!stack.empty()) {
            int[] pair = stack.pop();
            path[pair[0]] = pair[1];
            // if the next item in the vertical array is unassigned
            int target = getNeighbor(pair[0], step);
            if (path[target] < 0) {
                // the next item is always assigned the opposite of this item,
                // unless it was part of path/cycle of previous node
                stack.push(new int[]{target, pair[1] ^ 1});
            }
            idx = perms[getNeighbor(invPerms[pair[0]], step)];
            if (path[idx] < 0) {
                stack.push(new int[]{idx, pair[1] ^ 1});
            }
        }
    }

    private int getNeighbor(int index, int step) {
        return index < step ? index + step : index - step;
    }

    private int subHalf(int index, int step) {
        return index < step ? index : index - step;
    }

    @Override
    public PermutationNetworkType getType() {
        return PermutationNetworkType.TOP_WAKSMAN;
    }
}
