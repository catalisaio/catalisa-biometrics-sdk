package app.catalisa.biometrics;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The vectors are shared by every SDK in this repository and were produced by the
 * building block's own signing code, so "it passes here" means the same thing in
 * each language. They are read from the shared file rather than copied, so a
 * regenerated vector cannot leave one language behind.
 */
final class Vectors {

    private Vectors() {
    }

    static JsonNode load() {
        Path path = Path.of("..", "..", "vectors", "vectors.json");
        try {
            return BiometricsClient.MAPPER.readTree(Files.readString(path));
        } catch (IOException e) {
            throw new UncheckedIOException("vectors not found at " + path.toAbsolutePath(), e);
        }
    }
}
