package reductions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import algebra.SimplePolynomial;
import dhi.DHI_Challenge;
import dhi.I_DHI_Challenger;
import dy05.DY05_PK;
import dy05.I_Selective_DY05_Adversary;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

// Own imports
import java.security.SecureRandom;

public class DHI_DY05_Reduction implements I_DHI_DY05_Reduction {
    // Do not remove this field!
    private final I_Selective_DY05_Adversary adversary;

    private IGroupElement g;
    private BigInteger p;
    private int q;

    private IGroupElement ga;   // g^a

    private SimplePolynomial f;
    private BigInteger beta;

    private int x0;


    private SecureRandom random = new SecureRandom();

    public DHI_DY05_Reduction(I_Selective_DY05_Adversary adversary) {
        // Do not change this constructor!
        this.adversary = adversary;
    }

    @Override
    public IGroupElement run(I_DHI_Challenger challenger) {
        // Write Code here!

        var challenge = challenger.getChallenge();
        this.g = challenge.get(0);
        this.ga = challenge.get(1);
        this.p = g.getGroupOrder();

        this.q = challenge.size() - 1;      // message size (?)

        // You can use the SimplePolynomial class to solve this task
        var coefficients = new BigInteger[this.q];         // c_j
        for (int i = 0; i < coefficients.length; i++) {
            coefficients[i] = NumberUtils.getRandomBigInteger(random, this.p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        }
        this.f = new SimplePolynomial(p, coefficients);


        var ga = challenge.get(1);       // g^(a^1)
        if (ga.equals(g)) {                // g^(a^1) == g   ==> a = 1 ==> g^(1/a) = g^(1) = g
            return g;       
        }

        var result = adversary.run(this);

        while (this.x0 != 0) {
            result = adversary.run(this);       // g^(1/(alpha + x0))
        }
        return result;
    }

    @Override
    public void receiveChallengePreimage(int _challenge_preimage) throws Exception {
        // Write Code here!
        //System.out.println("receiveChallengePreimage: " + _challenge_preimage);
        this.x0 = _challenge_preimage;
    }

    @Override
    public IGroupElement eval(int preimage) {
        // Write Code here!
        System.out.println("eval");



        // this is basically the sign function (??)
        var zPlusXi = new SimplePolynomial(this.p, new int[] {preimage, 1});         // (z + xi)     and xi = preimage (?)
        var fiz = this.f.div(zPlusXi);                       // fi(z) = f(z) / (z + xi)
        var fibeta = this.g.power(fiz.eval(this.beta));     // g^(fi(beta)) = y = signature
        return fibeta;
    }

    @Override
    public DY05_PK getPK() {
        // Write Code here!
        return new DY05_PK(this.g, this.ga);
    }
}
