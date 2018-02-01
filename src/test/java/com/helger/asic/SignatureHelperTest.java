package com.helger.asic;

import static org.junit.Assert.fail;

import org.junit.Test;

public final class SignatureHelperTest
{
  @SuppressWarnings ("unused")
  @Test
  public void loadNoProblems ()
  {
    new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"), "changeit", null, "changeit");
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeystorePassword ()
  {
    try
    {
      new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"), "changed?", null, "changeit");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyPassword ()
  {
    try
    {
      new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"), "changeit", null, "changed?");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @SuppressWarnings ("unused")
  @Test
  public void wrongKeyAlias ()
  {
    try
    {
      new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"), "changeit", "asic", "changeit");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }
}
