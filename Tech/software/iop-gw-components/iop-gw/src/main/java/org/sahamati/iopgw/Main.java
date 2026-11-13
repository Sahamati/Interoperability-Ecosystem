package org.sahamati.iopgw;

import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.ConfigLoader;
import org.sahamati.iopgw.obs.Logs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/** Entry point: {@code java -jar iop-gw.jar [config.yaml]}. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "config.yaml");
        Logs.configure("INFO");
        Logger log = LoggerFactory.getLogger(Main.class);
        ConfigLoader loader = new ConfigLoader(System.getenv());
        Config c;
        try {
            c = loader.load(file);
        } catch (ConfigLoader.ConfigException e) {
            for (String err : e.errors) {
                log.atError().addMarker(Logs.CRITICAL).addKeyValue("error", err).log("invalid configuration");
            }
            System.exit(2);
            return;
        }
        Logs.configure(c.logging.level);
        log = LoggerFactory.getLogger(Main.class);
        for (String w : loader.warnings()) {
            log.atWarn().log(w);
        }
        Bootstrap.Running running;
        try {
            running = Bootstrap.start(c);
        } catch (Exception e) {
            log.atError().addMarker(Logs.CRITICAL).addKeyValue("error", e.getClass().getSimpleName())
                    .addKeyValue("reason", String.valueOf(e.getMessage())).log("gateway failed to start");
            System.exit(1);
            return;
        }
        log.atInfo().addKeyValue("mode", c.mode).addKeyValue("self", c.self.id).log("IOP Gateway started");
        CountDownLatch stop = new CountDownLatch(1);
        Bootstrap.Running r = running;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LoggerFactory.getLogger(Main.class).atInfo().log("shutting down");
            r.close();
            stop.countDown();
        }));
        stop.await();
    }
}
