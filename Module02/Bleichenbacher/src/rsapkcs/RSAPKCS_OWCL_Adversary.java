package rsapkcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

import static utils.NumberUtils.getRandomBigInteger;
import static utils.NumberUtils.ceilDivide;
import static utils.NumberUtils.getCeilLog;

import java.security.SecureRandom;

public class RSAPKCS_OWCL_Adversary implements I_RSAPKCS_OWCL_Adversary {

    private I_RSAPKCS_OWCL_Challenger challenger;

    private BigInteger c;       // Ciphertext
    private BigInteger n;
    private BigInteger e;

    private BigInteger B;
    private BigInteger TwoB;
    private BigInteger ThreeB;

    private SecureRandom random = new SecureRandom();

    public RSAPKCS_OWCL_Adversary() {
        // Do not change this constructor!
    }

    /*
     * @see basics.IAdversary#run(basics.IChallenger)
     */
    @Override
    public BigInteger run(final I_RSAPKCS_OWCL_Challenger challenger) {
        // Write code here

        this.challenger = challenger;
        this.c = challenger.getChallenge();      // ciphertext
        var pk = challenger.getPk();        // pk = (N, e)
        this.n = pk.N;
        this.e = pk.exponent;

        var k = (int) Math.ceil(n.bitLength() / 8.0);   // byte length of N
        this.B = BigInteger.TWO.pow(8 * (k - 2));       // 2^(8(k-2))
        this.TwoB = this.B.multiply(BigInteger.TWO);
        this.ThreeB = this.B.multiply(BigInteger.valueOf(3));

        System.out.println(k);
        System.out.println(challenger.getPlainTextLength());

        var step1 = step1();
        var s0 = step1.first;
        var c0 = step1.second;
        var Mi = step1.third;       // M0
        var i = 1;

        var si = s0;

        while (true) {
            si = step2(si, c0, Mi, i);

            Mi = step3(Mi, si);
    
            if (Mi.size() == 1 && Mi.get(0).first.equals(Mi.get(0).second)) {
                var a = Mi.get(0).first;
                var padded = a.multiply(s0.modInverse(this.n)).mod(this.n);

                // unpad the message
                var paddedBinary = padded.toString(2);
                var m = paddedBinary.substring(paddedBinary.length() - challenger.getPlainTextLength() * 8);
                return new BigInteger(m, 2);
            }
            else {
                i++;
            }
        }
    }

    private Triple<BigInteger, BigInteger, ArrayList<Pair<BigInteger, BigInteger>>> step1() {
        var s0 = NumberUtils.getRandomBigInteger(random, this.n);      // correct range??
        var test = getTestCipherText(c, s0);   // c(s0)^e mod N

        while (true) {
            try {
                if (challenger.isPKCSConforming(test)) break;
            } catch (Exception e) {
                // TODO Auto-generated catch block
                System.out.println("Caught exception in step 1");
                e.printStackTrace();
            }

            s0 = NumberUtils.getRandomBigInteger(random, this.n); 
            test = getTestCipherText(c, s0);
        }

        var c0 = test;
        var interval = new Pair<BigInteger, BigInteger>(this.TwoB, this.ThreeB.subtract(BigInteger.ONE));
        var M0 = new ArrayList<Pair<BigInteger, BigInteger>>();
        M0.add(interval);

        return new Triple<BigInteger, BigInteger, ArrayList<Pair<BigInteger, BigInteger>>>(s0, c0, M0);
    }

    private BigInteger step2(BigInteger prevS, BigInteger c0, ArrayList<Pair<BigInteger, BigInteger>> prevM, int i) {
        if (i == 1) {           // Step 2a
            var s1 = NumberUtils.ceilDivide(this.n, this.ThreeB);
            var test = getTestCipherText(c0, s1);

            while (true) {
                try {
                    if (challenger.isPKCSConforming(test)) break;
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    System.out.println("Caught exception in step 2a");
                    e.printStackTrace();
                }

                s1 = s1.add(BigInteger.ONE);
                test = getTestCipherText(c0, s1);
            }

            return s1;
        }
        else {
            if (prevM.size() >= 2) {        // Step 2b
                var si = prevS.add(BigInteger.ONE);
                var test = getTestCipherText(c0, si);

                while (true) {
                    try {
                        if (challenger.isPKCSConforming(test)) break;
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        System.out.println("Caught exception in step 2b");
                        e.printStackTrace();
                    }

                    si = si.add(BigInteger.ONE);
                    test = getTestCipherText(c0, si);
                }

                return si;
            }
            else {          // Step 2c
                var a = prevM.get(0).first;
                var b = prevM.get(0).second;

                var ri = NumberUtils.ceilDivide(BigInteger.TWO.multiply((b.multiply(prevS)).subtract(TwoB)), this.n);
                BigInteger si = null; 

                var found = false;
                while (!found) {
                    var lower = NumberUtils.ceilDivide((TwoB.add(ri.multiply(this.n))), b); // (TwoB.add(ri.multiply(this.N))).multiply(b.modInverse(this.N));
                    var uppper = NumberUtils.ceilDivide((ThreeB.add(ri.multiply(this.n))), a); // (ThreeB.add(ri.multiply(this.N))).multiply(a.modInverse(this.N));

                    for (si = lower; si.compareTo(uppper) <= 0; si = si.add(BigInteger.ONE)) {
                        var test = getTestCipherText(c0, si);
                        
                        try {
                            if (challenger.isPKCSConforming(test)) {
                                found = true;
                                break;
                            }
                        } catch (Exception e) {
                            // TODO Auto-generated catch block
                            System.out.println("Caught exception in step 2c");
                            e.printStackTrace();
                            si = si.subtract(BigInteger.ONE);       // Try again
                        }
                    }

                    ri = ri.add(BigInteger.ONE);
                }

                return si;
            }
        }
    }

    private ArrayList<Pair<BigInteger, BigInteger>> step3(ArrayList<Pair<BigInteger, BigInteger>> prevM, BigInteger si) {
        var newM = new ArrayList<Pair<BigInteger, BigInteger>>();
        
        for (var interval : prevM) {
            var a = interval.first;
            var b = interval.second;

            var lower = NumberUtils.ceilDivide((a.multiply(si).subtract(ThreeB).add(BigInteger.ONE)), this.n);
            var upper = (b.multiply(si).subtract(TwoB)).divide(this.n.add(BigInteger.ONE));

            for (var r = lower; r.compareTo(upper) <= 0; r = r.add(BigInteger.ONE)) {
                //System.out.println(r);
                var tmp1 = NumberUtils.ceilDivide((TwoB.add(r.multiply(this.n))), si);
                var intervalLow = a.max(tmp1);

                var tmp2 = (ThreeB.subtract(BigInteger.ONE).add(r.multiply(this.n))).divide(si);
                var intervalHigh = b.min(tmp2);

                newM = checkOverlaps(newM, intervalLow, intervalHigh);
            }
        }

        return newM;
    }

    private ArrayList<Pair<BigInteger, BigInteger>> checkOverlaps(ArrayList<Pair<BigInteger, BigInteger>> newM, BigInteger low, BigInteger high) {
        for (var i = 0; i < newM.size(); i++) {
            var interval = newM.get(i);
            var a = interval.first;
            var b = interval.second;

            if (a.compareTo(high) <= 0 && b.compareTo(low) >= 0) {
                var newA = a.min(low);
                var newB = b.max(high);

                newM.set(i, new Pair<BigInteger,BigInteger>(newA, newB));
                return newM;
            }
        }

        newM.add(new Pair<BigInteger,BigInteger>(low, high));
        return newM;
    }

    private BigInteger getTestCipherText(BigInteger c, BigInteger s) {
        return c.multiply(s.modPow(this.e, this.n)).mod(this.n);
    }
}