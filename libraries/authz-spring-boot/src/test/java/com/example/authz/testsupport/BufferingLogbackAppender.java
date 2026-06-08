package com.example.authz.testsupport;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Logback appender that buffers formatted log lines in memory instead of
 * printing them. {@link LogFlushExtension} drains the buffer to stdout only when
 * a test fails, so a green test run stays quiet while a failing test still shows
 * everything it (and the library) logged.
 *
 * <p>JUnit Jupiter runs tests sequentially by default, so a single static buffer
 * is sufficient — the extension clears it before each test and drains/clears it
 * on the test's outcome.
 */
public class BufferingLogbackAppender extends AppenderBase<ILoggingEvent> {

  private static final List<String> BUFFER = Collections.synchronizedList(new ArrayList<>());

  private PatternLayout layout;

  @Override
  public void start() {
    layout = new PatternLayout();
    layout.setContext(getContext());
    layout.setPattern("%d{HH:mm:ss.SSS} %-5level %logger{36} - %msg%n");
    layout.start();
    super.start();
  }

  @Override
  protected void append(ILoggingEvent event) {
    if (layout != null) {
      BUFFER.add(layout.doLayout(event));
    }
  }

  /** Discard any buffered lines (called before each test). */
  public static void clear() {
    BUFFER.clear();
  }

  /** Return and remove all buffered lines (called when a test fails). */
  public static List<String> drain() {
    synchronized (BUFFER) {
      List<String> copy = new ArrayList<>(BUFFER);
      BUFFER.clear();
      return copy;
    }
  }
}
