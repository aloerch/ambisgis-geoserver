/* (c) 2026 AmbisGIS contributors.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.importer.job;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Test-only access to the existing package-private executors; no production API or reflection. */
public final class JobQueueShutdownProbe {
    private JobQueueShutdownProbe() {}

    public static boolean cleanerIsDaemon(JobQueue queue) throws Exception {
        return queue.cleaner.submit(() -> Thread.currentThread().isDaemon()).get(2, TimeUnit.SECONDS);
    }

    public static void assertStopped(JobQueue queue) throws InterruptedException {
        assertTrue("queue cleaner must be shut down", queue.cleaner.isShutdown());
        assertTrue("queue worker pool must be shut down", queue.pool.isShutdown());
        assertTrue("queue cleaner must terminate", queue.cleaner.awaitTermination(2, TimeUnit.SECONDS));
        assertTrue("queue worker pool must terminate", queue.pool.awaitTermination(2, TimeUnit.SECONDS));
    }

    public static void cleanup(JobQueue... queues) throws InterruptedException {
        // Always stop every owned queue before any termination assertion can fail.
        for (JobQueue queue : queues) queue.shutdown();
        boolean stopped = true;
        for (JobQueue queue : queues) {
            stopped &= queue.cleaner.awaitTermination(2, TimeUnit.SECONDS);
            stopped &= queue.pool.awaitTermination(2, TimeUnit.SECONDS);
        }
        assertTrue("all test-owned executors must terminate, including baseline failures", stopped);
    }

    public static Worker startWorker(JobQueue queue) throws InterruptedException {
        return new Worker(queue);
    }

    public static final class Worker implements AutoCloseable {
        private final CountDownLatch release = new CountDownLatch(1);
        private final CountDownLatch started = new CountDownLatch(1);
        private final Future<?> future;
        private volatile boolean interrupted;

        private Worker(JobQueue queue) throws InterruptedException {
            future = queue.pool.submit(() -> {
                started.countDown();
                try {
                    // A finite backstop exists even if a test assertion fails before shutdown.
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException expected) {
                    interrupted = true;
                    Thread.currentThread().interrupt();
                }
            });
            if (!started.await(2, TimeUnit.SECONDS)) {
                release.countDown();
                throw new AssertionError("test-owned queue worker did not start");
            }
        }

        public void assertInterrupted() {
            assertTrue("destroy must interrupt an active worker", interrupted);
        }

        @Override
        public void close() throws Exception {
            release.countDown();
            future.get(2, TimeUnit.SECONDS);
        }
    }
}
