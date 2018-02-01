package no.difi.asic;

import static org.junit.Assert.fail;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureHelperTest
{

  private static Logger log = LoggerFactory.getLogger (SignatureHelperTest.class);

  @Test
  public void loadNoProblems ()
  {
    new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"), "changeit", null, "changeit");
  }

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
      log.info (e.getMessage ());
    }
  }

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
      log.info (e.getMessage ());
    }
  }

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
      log.info (e.getMessage ());
    }
  }
}
