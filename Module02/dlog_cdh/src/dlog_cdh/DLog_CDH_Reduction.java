package dlog_cdh;

import java.math.BigInteger;
import java.util.Random;

import javax.security.auth.kerberos.KerberosCredMessage;

import cdh.CDH_Challenge;
import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

// Own imports
import java.util.ArrayList;

/**
 * This is the file you need to implement.
 * 
 * Implement the method {@code run} of this class.
 * Do not change the constructor of this class.
 */
public class DLog_CDH_Reduction extends A_DLog_CDH_Reduction<IGroupElement, BigInteger> {

    /**
     * You will need this field.
     */
    private CDH_Challenge<IGroupElement> cdh_challenge;
    /**
     * Save here the group generator of the DLog challenge given to you.
     */
    private IGroupElement g;
    private IGroupElement gx;        // g^x

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public DLog_CDH_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();
        this.g = challenge.generator;
        this.gx = challenge.x;       // g^x
        var p = challenge.generator.getGroupOrder();
        var phi = p.subtract(BigInteger.ONE);      // phi(p) = p - 1


        if (this.gx.equals(this.g.power(BigInteger.ZERO))) {
            return BigInteger.ZERO;
        }

        if (this.gx.equals(this.g)) {
            return BigInteger.ONE;
        }


        // You may assume that adversary is a perfect adversary.
        // I.e., cdh_solution will always be of the form g^(x * y) when you give the
        // adversary g, g^x and g^y in the getChallenge method below.

        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        // Make use of the fact that the group order is of the form 1 + p1 * ... * pn
        // for many small primes pi !!
        int[] primes = PrimesHelper.getDecompositionOfPhi(p);      // qs

        // Also, make use of a generator of the multiplicative group mod p.
        BigInteger z = PrimesHelper.getGenerator(p);     

        // You can also use the method of CRTHelper
        //int[] values = new int[primes.length];
        //BigInteger composed = CRTHelper.crtCompose(values, primes);


        // We know that x = z^k --> find k using Pohlig-Hellman algorithm
        var crtValues = new ArrayList<Integer>();
        var crtModuli = new ArrayList<Integer>();

        for (int qi : primes) {
            var phiDivQi = phi.divide(BigInteger.valueOf(qi));

            var gxPhiDivQi = cdh_power(this.gx, phiDivQi);      // g^(x^(phi/qi))

            var zPhiDivQi = z.modPow(phiDivQi, p);         // z^(phi/qi)

            for (int r = 0; r < qi; r++) {
                var zKPhiDivQi = zPhiDivQi.pow(r);              // z^(r * (phi/qi))
                var gzKPhiDivQi = this.g.power(zKPhiDivQi);     // g^(z^(r * (phi/qi)))

                if (gxPhiDivQi.equals(gzKPhiDivQi)) {
                    crtValues.add(r);
                    crtModuli.add(qi);
                }
            }
        }

        var values = new int[crtValues.size()];
        var moduli = new int[crtModuli.size()];

        for (int i = 0; i < crtValues.size(); i++) {
            values[i] = crtValues.get(i);
            moduli[i] = crtModuli.get(i);
        }

        var k = CRTHelper.crtCompose(values, moduli);
        return z.modPow(k, p);
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        // There is not really a reason to change any of the code of this method.
        return cdh_challenge;
    }

    /**
     * For your own convenience, you should write a cdh method for yourself that,
     * when given group elements g^x and g^y, returns a group element g^(x*y)
     * (where g is the generator from the DLog challenge).
     */
    private IGroupElement cdh(IGroupElement x, IGroupElement y) {

        cdh_challenge = new CDH_Challenge<IGroupElement>(this.g, x, y);

        // Use the run method of your CDH adversary to have it solve CDH-challenges:
        // You should specify the challenge in the cdh_challenge field of this class.
        // So, the above getChallenge method returns the correct cdh challenge to
        // adversary.
        return adversary.run(this);
    }

    /**
     * For your own convenience, you should write a cdh_power method for yourself
     * that,
     * when given a group element g^x and a number k, returns a group element
     * g^(x^k) (where g is the generator from the DLog challenge).
     */
    private IGroupElement cdh_power(IGroupElement x, BigInteger exponent) {
        // For this method, use your cdh method and think of aritmetic algorithms for
        // fast exponentiation.
        // Use the methods exponent.bitLength() and exponent.testBit(n)!

        // Square-and-Multiply

        if (exponent.equals(BigInteger.ZERO)) {
            return this.g;
        }

        if (!exponent.testBit(0)) {
            // exponent is even
            return cdh_power(cdh(x, x), exponent.divide(BigInteger.TWO));
        }
        else {
            // exponent is odd
            var tmp = cdh_power(cdh(x, x), (exponent.subtract(BigInteger.ONE)).divide(BigInteger.TWO));
            return cdh(x, tmp);
        }
    }
}
