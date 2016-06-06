package org.shu.zq.crypto

import java.math.BigInteger
import java.security.{SecureRandom, KeyPairGenerator, Security, KeyPair}

import com.typesafe.scalalogging.Logger
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory

/**
  * Created by Qiang on 3/16/2016.
  */
object KeyGenerator {
  val ALGORITHM = "RSA"
  val PROVIDER = "BC"
  val KEY_LENGTH = 2048

  def get(len: Int = KEY_LENGTH) : KeyPair = {
    Security.addProvider(new BouncyCastleProvider)
    val keyGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER)
    keyGen.initialize(len)
    return keyGen.generateKeyPair()
  }

  private val random = new SecureRandom()
  def getRandomString(len : Int = 32) : String = new BigInteger(130, random).toString(32).substring(0, len+1)

  val logger = Logger(LoggerFactory.getLogger(KeyGenerator.getClass.getName.split("\\$").last))
}
