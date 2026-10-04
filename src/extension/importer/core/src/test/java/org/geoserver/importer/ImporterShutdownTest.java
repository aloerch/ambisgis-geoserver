/* (c) 2026 AmbisGIS contributors.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.importer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import java.net.URI;
import java.nio.file.Path;
import org.geoserver.importer.job.JobQueue;
import org.geoserver.importer.job.JobQueueShutdownProbe;
import org.geoserver.platform.resource.Resource;
import org.junit.Before;
import org.junit.Test;

/** Exercises the actual importer and both real queue executors without starting Spring or an import. */
public class ImporterShutdownTest {
    @Before
    public void verifySelectedClassOrigins() throws Exception {
        if (System.getProperty("ambisgis.importer.origin") == null
                && System.getProperty("ambisgis.jobqueue.origin") == null
                && System.getProperty("ambisgis.tests.origin") == null) {
            // Ordinary reactor tests load both production classes from this module,
            // and both test classes from its separate test output directory.
            assertEquals(origin(Importer.class), origin(JobQueue.class));
            assertEquals(origin(ImporterShutdownTest.class), origin(JobQueueShutdownProbe.class));
            assertNotEquals(origin(Importer.class), origin(ImporterShutdownTest.class));
            return;
        }
        // The direct predecessor/successor replay supplies all three exact origins.
        assertOrigin(Importer.class, "ambisgis.importer.origin");
        assertOrigin(JobQueue.class, "ambisgis.jobqueue.origin");
        assertOrigin(ImporterShutdownTest.class, "ambisgis.tests.origin");
        assertOrigin(JobQueueShutdownProbe.class, "ambisgis.tests.origin");
    }

    private static void assertOrigin(Class<?> type, String property) throws Exception {
        String expected = System.getProperty(property);
        if (expected == null) throw new AssertionError("Missing exact class origin: " + property);
        assertEquals(Path.of(expected).toRealPath(), origin(type));
    }

    private static Path origin(Class<?> type) throws Exception {
        URI actual = type.getProtectionDomain().getCodeSource().getLocation().toURI();
        return Path.of(actual).toRealPath();
    }

    private static Importer importer(CountingStore store) {
        ImporterInfoDAO config = new ImporterInfoDAO() {
            @Override
            ImporterInfo read(Resource resource) {
                ImporterInfoImpl info = new ImporterInfoImpl();
                info.setMaxAsynchronousImports(1);
                info.setMaxSynchronousImports(1);
                return info;
            }
        };
        // No catalog operation is exercised. The finite DAO returns defaults on the
        // constructor's existing no-application-context fallback, without file reads.
        Importer importer = new Importer(null, config);
        importer.contextStore = store;
        return importer;
    }

    @Test
    public void idleDestroyTerminatesBothQueues() throws Exception {
        CountingStore store = new CountingStore();
        Importer importer = importer(store);
        try {
            assertFalse(JobQueueShutdownProbe.cleanerIsDaemon(importer.asynchronousJobs));
            assertFalse(JobQueueShutdownProbe.cleanerIsDaemon(importer.synchronousJobs));
            importer.destroy();
            assertEquals(1, store.destroyCalls);
            JobQueueShutdownProbe.assertStopped(importer.asynchronousJobs);
            JobQueueShutdownProbe.assertStopped(importer.synchronousJobs);
        } finally {
            JobQueueShutdownProbe.cleanup(importer.asynchronousJobs, importer.synchronousJobs);
        }
    }

    @Test
    public void destroyInterruptsBothActiveWorkersAndTerminatesCleaners() throws Exception {
        CountingStore store = new CountingStore();
        Importer importer = importer(store);
        try {
            try (JobQueueShutdownProbe.Worker async = JobQueueShutdownProbe.startWorker(importer.asynchronousJobs);
                    JobQueueShutdownProbe.Worker sync = JobQueueShutdownProbe.startWorker(importer.synchronousJobs)) {
                importer.destroy();
                assertEquals(1, store.destroyCalls);
                JobQueueShutdownProbe.assertStopped(importer.asynchronousJobs);
                JobQueueShutdownProbe.assertStopped(importer.synchronousJobs);
                async.assertInterrupted();
                sync.assertInterrupted();
            }
        } finally {
            JobQueueShutdownProbe.cleanup(importer.asynchronousJobs, importer.synchronousJobs);
        }
    }

    @Test
    public void repeatedDestroyKeepsQueuesStoppedAndCallsRepeatSafeStore() throws Exception {
        CountingStore store = new CountingStore();
        Importer importer = importer(store);
        try {
            importer.destroy();
            importer.destroy();
            assertEquals(2, store.destroyCalls);
            JobQueueShutdownProbe.assertStopped(importer.asynchronousJobs);
            JobQueueShutdownProbe.assertStopped(importer.synchronousJobs);
        } finally {
            JobQueueShutdownProbe.cleanup(importer.asynchronousJobs, importer.synchronousJobs);
        }
    }

    private static final class CountingStore extends MemoryImportStore {
        int destroyCalls;

        @Override
        public void destroy() {
            destroyCalls++;
            super.destroy();
        }
    }
}
