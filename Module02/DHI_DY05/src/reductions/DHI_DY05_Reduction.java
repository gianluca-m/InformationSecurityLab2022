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
import java.util.HashMap;

public class DHI_DY05_Reduction implements I_DHI_DY05_Reduction {
    // Do not remove this field!
    private final I_Selective_DY05_Adversary adversary;

    private DHI_Challenge challenge;
    private IGroupElement g;
    private IGroupElement ga;   // g^a
    private IGroupElement g0;   // g^0
    private BigInteger p;
    private int q;

    private SimplePolynomial f;     // f(z)
    private BigInteger x0;
    
    private HashMap<Integer, IGroupElement> binomials;      // i -> g^((beta)^i) = g^((alpha - x0)^i)
    private HashMap<Pair<Integer, Integer>, Integer> binomialCoefficients = new HashMap<Pair<Integer, Integer>, Integer>();

    public DHI_DY05_Reduction(I_Selective_DY05_Adversary adversary) {
        // Do not change this constructor!
        this.adversary = adversary;
    }

    @Override
    public IGroupElement run(I_DHI_Challenger challenger) {
        // Write Code here!

        this.challenge = challenger.getChallenge();
        this.g = challenge.get(0);
        this.ga = challenge.get(1);     // g^(a^1) = g^a
        this.g0 = this.g.power(BigInteger.ZERO);
        this.p = g.getGroupOrder();
        this.q = challenge.size() - 1;      // message size (?)

        // You can use the SimplePolynomial class to solve this task

        // Base case
        if (this.ga.equals(g)) {                // g^(a^1) == g^a == g   ==> a = 1 ==> g^(1/a) = g^(1) = g
            return g;       
        }

        // General case
        var sigma = adversary.run(this);

        var zPlusX0 = new SimplePolynomial(this.p, new BigInteger[] {this.x0, BigInteger.ONE});     // (z + x0)
        var fzDivZPlusX0 = this.f.div(zPlusX0);     // f(z) / (z + x0)
        var gammaMinus1 = this.f.subtract(fzDivZPlusX0.multiply(zPlusX0));      // gamma-1  = remainder of polynomial division
        
        var prod = this.g.power(BigInteger.ZERO);
        for (int j = 0; j <= q - 2; j++) {
            var gBetaj = this.binomials.get(j);                         // g^(beta^j)
            var tmp = gBetaj.power(fzDivZPlusX0.get(j)).invert();       // (g^(beta^j))^(-gamma_j)
            prod = prod.multiply(tmp);
        }

        var gammaMinus1Inverse = gammaMinus1.get(0).modInverse(this.p);
        var gaInverse = sigma.multiply(prod).power(gammaMinus1Inverse);
        return gaInverse;
    }

    @Override
    public void receiveChallengePreimage(int _challenge_preimage) throws Exception {
        // Write Code here!
        this.x0 = BigInteger.valueOf(_challenge_preimage);
    }

    @Override
    public IGroupElement eval(int preimage) {
        // Write Code here!

        var zPlusXi = new SimplePolynomial(this.p, new BigInteger[] {BigInteger.valueOf(preimage), BigInteger.ONE});         // (z + xi)     and xi = preimage (?)
        var fiz = this.f.div(zPlusXi);                       // fi(z) = f(z) / (z + xi)

        var sign = this.g0;
        for (int j = 0; j <= q - 2; j++) {
            var gBetaj = this.binomials.get(j);     // g^(beta^j)
            var tmp = gBetaj.power(fiz.get(j));     // (g^(beta^j))^d_j
            sign = sign.multiply(tmp);
        }

        return sign;     // g^(fi(beta)) = h^(1/(xi + beta))
    }

    @Override
    public DY05_PK getPK() {
        // Write Code here!

        setupPolynomial(q);
        setupBinomials(q);

        var h = this.g0;
        for (int j = 0; j <= q - 1; j++) {
            var gBetaj = this.binomials.get(j);         // g^(beta^j)
            var tmp = gBetaj.power(this.f.get(j));      // (g^(beta^j))^c_j
            h = h.multiply(tmp);
        }

        var hBeta = this.g0;
        for (int j = 1; j <= q; j++) {
            var gBetaj = this.binomials.get(j);             // g^(beta^j)
            var tmp = gBetaj.power(this.f.get(j - 1));      // (g^(beta^j))^c_(j-1)
            hBeta = hBeta.multiply(tmp);
        }

        return new DY05_PK(h, hBeta);
    }

    private void setupPolynomial(int q) {
        var poly = new SimplePolynomial(this.p, BigInteger.ONE);

        for (int w = 0; w <= q - 1; w++) {
            if (BigInteger.valueOf(w).equals(this.x0)) continue;

            var tmp = new SimplePolynomial(this.p, new BigInteger[] {BigInteger.valueOf(w), BigInteger.ONE});
            poly = poly.multiply(tmp);
        }

        this.f = poly;
    }

    private void setupBinomials(int q) {
        binomials = new HashMap<Integer, IGroupElement>();
        binomials.put(0, this.g);
        binomials.put(1, this.ga.multiply(this.g.power(this.x0).invert()));

        for (int n = 2; n <= q; n++) {
            var res = this.g0;
            for (int k = 0; k <= n; k++) {
                // coefficient = binCoeff(n, k)
                // alpha exponent = k
                // x0 exponent = n - k

                var c = BigInteger.valueOf(binCoeff(n, k)).multiply(this.x0.pow(n - k));       // coeff * x0^exponent
                var tmp = this.challenge.get(k).power(c);

                if ((n - k) % 2 != 0) {
                    tmp = tmp.invert();
                }

                res = res.multiply(tmp);
            }

            binomials.put(n, res);      // n -> g^((alpha - x0)^n) = g^(beta^n)
        }
    }

    private int binCoeff(int n, int k) {
        var key = new Pair<Integer, Integer>(n, k);
        if (binomialCoefficients.containsKey(key)) {
            return binomialCoefficients.get(key);
        }

        if ((n == k) || (k == 0)) return 1;

        var coeff = binCoeff(n - 1, k) + binCoeff(n - 1, k - 1);
        binomialCoefficients.put(key, coeff);
        return coeff;
    }
}
