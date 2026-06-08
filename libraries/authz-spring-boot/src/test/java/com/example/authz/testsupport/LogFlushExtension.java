package com.example.authz.testsupport;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

import java.util.List;
import java.util.Optional;

/**
 * Quiet-on-success, loud-on-failure log routing for the test suite.
 *
 * <p>Clears the {@link BufferingLogbackAppender} before each test and replays the
 * buffered log lines to stdout only when that test fails. Auto-registered for the
 * whole module via {@code junit-platform.properties}
 * ({@code junit.jupiter.extensions.autodetection.enabled=true}) plus the
 * {@code META-INF/services} entry — no per-test annotation needed.
 */
public class LogFlushExtension implements BeforeEachCallback, TestWatcher {

  @Override
  public void beforeEach(ExtensionContext context) {
    BufferingLogbackAppender.clear();
  }

  @Override
  public void testFailed(ExtensionContext context, Throwable cause) {
    List<String> lines = BufferingLogbackAppender.drain();
    if (lines.isEmpty()) return;
    StringBuilder sb = new StringBuilder();
    sb.append("\n--- captured logs for failed test: ").append(context.getDisplayName()).append(" ---\n");
    for (String line : lines) sb.append(line);
    sb.append("--- end captured logs ---\n");
    System.out.print(sb);
  }

  @Override
  public void testSuccessful(ExtensionContext context) {
    BufferingLogbackAppender.clear();
  }

  @Override
  public void testAborted(ExtensionContext context, Throwable cause) {
    BufferingLogbackAppender.clear();
  }

  @Override
  public void testDisabled(ExtensionContext context, Optional<String> reason) {
    BufferingLogbackAppender.clear();
  }
}
