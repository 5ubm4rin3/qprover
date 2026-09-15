# Optimization-Guided Search for Stateful Test Ordering and Regression-Corpus Selection

**Research status:** scoped technical recommendation
**Last reviewed:** 2026-09-12
**Scope:** benign software-test scheduling and regression-suite optimization only

## Executive recommendation

Build one solver-independent binary quadratic model (BQM) interface, but make classical exact optimization and simulated annealing the reference implementations. Treat QAOA statevector simulation as a small-instance research backend, not as the default engine and not as evidence of quantum advantage.

Use two models rather than one oversized formulation:

1. **Select** a regression corpus under coverage, cost, and cardinality constraints.
2. **Order** the selected stateful tests using position-weighted utility and learned pairwise transition scores.

This separation keeps the main models interpretable, provides useful classical optimization immediately, and permits controlled solver comparisons. A joint selection-and-ordering model is included below for small experiments, but its $nK$ binary variables and dense couplings make it unsuitable as the primary design.

The research evidence supports QUBO as a useful common representation. It does **not** support a quantum-speedup claim. The strongest directly relevant studies are:

- Wang et al.'s **BootQA**, the first reported use of quantum annealing for classical-software test-case minimization. On three industrial datasets it found solution quality similar to the paper's simulated-annealing baseline, while relying on bootstrap decomposition to fit current hardware ([Wang et al., TOSEM 2024](https://doi.org/10.1145/3680467); [open preprint](https://arxiv.org/abs/2308.05505)).
- Wang et al.'s **IGDec-QAOA**, which formulated test-case selection/minimization as an Ising objective and evaluated ideal simulation, noisy simulation, and one small real-device study. It explicitly states that it does not demonstrate quantum advantage ([Wang et al., IEEE TSE 2024](https://doi.org/10.1109/TSE.2024.3479421); [open preprint](https://arxiv.org/abs/2312.15547)).
- Trovato et al.'s **QAOA-TCS**, a preliminary QAOA test-selection study using an ideal statevector simulator. The paper itself lists idealized simulation, implementation-language differences, hardware differences, hyperparameter tuning, and four GNU subjects as threats to validity ([Trovato et al., EASE Companion 2025](https://doi.org/10.1145/3727967.3756821); [open preprint](https://arxiv.org/abs/2504.18955)).
- Trovato et al.'s **SelectQA**, which reformulated coverage-preserving regression selection for quantum annealing and compared it with Additional Greedy, DIV-GA, and BootQA. Its reported timing mixes different execution environments and a managed hybrid solver, so the result is useful feasibility evidence rather than a hardware speedup result ([Trovato et al., STTT 2024](https://doi.org/10.1007/s10009-024-00775-w); [open preprint](https://arxiv.org/abs/2411.15963)).
- Sharma et al.'s 2026 ICST study is the newest directly relevant QAOA minimization work located. It adds adaptive multi-objective QUBO reweighting, batch-wise QAOA, and classical greedy/SA fallbacks on TCAS and Cerberus. Its public artifact improves reproducibility, but the result is too recent to treat as independently replicated ([paper DOI](https://doi.org/10.1109/ICST69053.2026.00093); [Zenodo artifact](https://doi.org/10.5281/zenodo.18897689)).

## 1. Why optimization is a good fit

Regression testing has three related but distinct problems:

- **Minimization:** choose a smallest or cheapest subset while retaining required test obligations.
- **Selection:** choose a subset that is most valuable for a particular revision and budget.
- **Prioritization:** order tests so useful information arrives earlier.

The classic prioritization definition is explicitly an ordering problem over a test suite with a chosen objective; rate of fault detection is one established objective ([Rothermel et al., ICSM 1999](https://doi.org/10.1109/ICSM.1999.792604)). Multi-objective minimization work also shows why cardinality alone is inadequate: cost, coverage, and historical effectiveness can conflict ([Yoo and Harman, JSS 2010](https://doi.org/10.1016/j.jss.2009.11.706)). Similarity-based prioritization provides empirical precedent for using relationships between tests rather than only independent per-test scores ([Ledru et al., ASE Journal 2012](https://doi.org/10.1007/s10515-011-0093-0); [Haghighatkhah et al., 2018](https://arxiv.org/abs/1809.00138)).

QUBO is a reasonable interchange format because linear objectives, pairwise interactions, equality penalties, and bounded integer slack can all be represented as a quadratic polynomial over binary variables. General mappings from covering and permutation problems to Ising models are well established ([Lucas 2014](https://doi.org/10.3389/fphy.2014.00005)), and practical formulation guidance is available in [Glover, Kochenberger, and Du 2019](https://doi.org/10.1007/s10288-019-00424-y).

The optimization model should remain subordinate to actual test outcomes. Historical scores propose a corpus and order; clean, controlled test execution measures whether those choices were useful.

## 2. Common notation and normalization

Let:

- $T=\{1,\ldots,n\}$ be available tests.
- $R=\{1,\ldots,m\}$ be regression obligations such as changed-code blocks, requirements, or mutation targets.
- $a_{ri}\in\{0,1\}$ indicate whether test $i$ covers obligation $r$.
- $c_i\ge 0$ be estimated execution cost.
- $\bar c_i\in[0,1]$ be the normalized execution cost used in a weighted objective.
- $h_i\in[0,1]$ be historical information value.
- $v_i\in[0,1]$ be revision-specific relevance.
- $R_{ij}\in[0,1]$ be a symmetric redundancy score for selecting both $i$ and $j$.
- $D_{ij}\in[-1,1]$ be the estimated value of running $j$ immediately after $i$.
- $d_p$ be a non-increasing positional discount, for example $d_p=1/p$ or $d_p=\rho^{p-1}$, $0<\rho<1$.

Normalize measured features on the training partition only. Record the scaler with each benchmark instance. Winsorization is preferable to min-max scaling when a few very slow tests would otherwise compress nearly every cost toward zero. If $D_{ij}$ is learned, preserve its sign: a negative transition can represent redundant or destabilizing adjacency, while a positive transition can represent useful state continuity or incremental coverage.

The canonical minimization-form QUBO is

\[
E(x)=x^\top Qx+\kappa,\qquad x\in\{0,1\}^N.
\]

Since $x_i^2=x_i$, linear coefficients live on the diagonal of $Q$. Fix one matrix convention in code: either an upper-triangular $Q$ whose off-diagonal coefficient is counted once, or a symmetric $Q$ with a documented factor of two. Never mix conventions across solvers.

For Ising backends, choose $x_i=(1-z_i)/2$, $z_i\in\{-1,+1\}$, and apply the substitution mechanically. Under this convention, $z_i=-1$ means the binary decision is selected.

## 3. QUBO A: regression-corpus selection

### 3.1 Native constrained problem

Let $y_i=1$ if test $i$ is selected. A useful native model is

\[
\begin{aligned}
\min_y\quad
& \lambda_c\sum_i \bar c_i y_i
-\lambda_h\sum_i h_i y_i
-\lambda_v\sum_i v_i y_i
+\lambda_r\sum_{i<j} R_{ij}y_i y_j \\
\text{s.t.}\quad
& \sum_i a_{ri}y_i\ge 1 && \forall r\in R_{\mathrm{hard}},\\
& \sum_i c_i y_i\le B && \text{if a budget is specified},\\
& L\le \sum_i y_i\le U && \text{if corpus-size bounds are specified}.
\end{aligned}
\]

$R_{ij}\ge0$ penalizes redundant pairs. The linear historical and revision scores reward independently useful tests; the quadratic term discourages choosing many tests that cover the same behavior. Weights $\lambda_*$ define a policy, not a solver setting, and must be fixed before evaluating solvers.

The coverage constraint should remain hard by default. A model that merely rewards total coverage can discard a rare obligation when common obligations carry enough aggregate reward.

### 3.2 Exact QUBO encoding of coverage

For obligation $r$, define $d_r=\sum_i a_{ri}$. Reject the instance as infeasible if $d_r=0$. When $d_r>1$, introduce nonnegative integer slack

\[
s_r=\sum_{b=0}^{\lceil\log_2 d_r\rceil-1}2^b u_{rb},
\qquad u_{rb}\in\{0,1\}.
\]

Set $s_r=0$ directly when $d_r=1$.

The at-least-one constraint becomes

\[
P_{\mathrm{cov},r}
=A_r\left(\sum_i a_{ri}y_i-1-s_r\right)^2.
\]

Because the squared expression is linear before expansion and every variable is binary, it expands to a QUBO. Extra binary representations above $d_r-1$ cannot satisfy the equality and therefore do not create false feasible solutions. The complete energy is

\[
E_{\mathrm{select}}(y,u)
=E_{\mathrm{policy}}(y)+\sum_{r\in R_{\mathrm{hard}}}P_{\mathrm{cov},r}
+P_{\mathrm{budget}}+P_{\mathrm{size}}.
\]

An integer budget can be encoded similarly:

\[
P_{\mathrm{budget}}
=A_B\left(B-\sum_i \tilde c_i y_i-\sum_b2^b q_b\right)^2,
\]

where $\tilde c_i$ and $B$ are consistently quantized integers, and the budget slack has enough bits to represent $0,\ldots,B$. Quantization error must be reported. For real-valued costs, keeping the budget in a native MILP/CP-SAT reference model is safer than silently rounding it.

Cardinality equality $\sum_i y_i=K$ needs no slack:

\[
P_K=A_K\left(K-\sum_i y_i\right)^2.
\]

### 3.3 Hard versus soft obligations

- Use a **hard constraint** when violating it invalidates the corpus, for example omitting a mandatory regression obligation.
- Use a **soft penalty** when a trade-off is meaningful, for example overlap, predicted information value, or a preferred but nonessential test family.
- Use a **lexicographic solve** when priorities are absolute: first minimize uncovered hard obligations, then execution cost, then cardinality. A single weighted sum can conceal this priority order.

In an unconstrained QUBO, “hard” means that the penalty provably dominates any objective improvement from violating the constraint. A conservative sufficient rule is

\[
A > \max_x E_{\mathrm{policy}}(x)-\min_x E_{\mathrm{policy}}(x),
\]

or any valid upper bound on that range. This is safe mathematically but can create a badly scaled energy landscape. Penalty calibration is therefore part of the formulation, and overly small and overly large weights can both harm heuristic solving ([Ayodele 2022](https://arxiv.org/abs/2206.11040)). Always validate the chosen $A$ by exact enumeration on small instances and report feasibility separately from objective quality.

## 4. QUBO B: ordering stateful tests

### 4.1 One-hot permutation encoding

After selection, suppose $k$ tests remain. Let $x_{ip}=1$ when selected test $i$ occupies position $p\in\{1,\ldots,k\}$. A full permutation requires:

\[
\sum_p x_{ip}=1\quad\forall i,
\qquad
\sum_i x_{ip}=1\quad\forall p.
\]

Encode both constraints as

\[
P_{\mathrm{perm}}
=A_{\mathrm{test}}\sum_i\left(1-\sum_p x_{ip}\right)^2
+A_{\mathrm{pos}}\sum_p\left(1-\sum_i x_{ip}\right)^2.
\]

This is the standard $k^2$-variable one-hot structure used by permutation and routing QUBOs; it provides a transparent correctness oracle but scales poorly ([Lucas 2014](https://doi.org/10.3389/fphy.2014.00005); [Ayodele 2022](https://arxiv.org/abs/2206.11040)).

### 4.2 Position and transition objective

Define independent utility $w_i=\alpha h_i+\beta v_i$, with $\alpha+\beta=1$. Then minimize

\[
\begin{aligned}
E_{\mathrm{order}}(x)=
&-\lambda_u\sum_{i,p}d_p w_i x_{ip}\\
&-\lambda_D\sum_{p=1}^{k-1}\sum_{i\ne j}D_{ij}x_{ip}x_{j,p+1}\\
&+P_{\mathrm{perm}}+P_{\mathrm{precedence}}+P_{\mathrm{forbidden}}.
\end{aligned}
\]

The first term moves independently valuable tests earlier. The second scores consecutive transitions and may be asymmetric: $D_{ij}\ne D_{ji}$. If every selected test always runs, $\sum_i c_i$ is constant and must not be added as a fake differentiating term. Cost matters through a time-discounted utility, an early-stop horizon, or a joint selection model.

This pairwise transition formulation is a proposed extension. The reviewed quantum-testing papers optimize selection/minimization, not learned state-transition ordering. Its usefulness must therefore be established empirically rather than attributed to those papers.

Examples of quadratic scheduling constraints are:

\[
P_{\mathrm{precedence}}(a\prec b)
=A_{ab}\sum_{p\ge q}x_{ap}x_{bq},
\]

which penalizes placing $a$ at or after $b$, and

\[
P_{\mathrm{forbidden}}(i,j)
=A_{ij}\sum_{p=1}^{k-1}x_{ip}x_{j,p+1},
\]

which forbids a directed adjacency. Fixed first or last tests should be handled by eliminating variables rather than adding penalties.

### 4.3 Joint select-and-order model for a fixed horizon

For a small experiment that chooses and orders exactly $K$ tests from $n$, use $x_{ip}$ for $i\in T$, $p\in\{1,\ldots,K\}$, and

\[
P_{\mathrm{slot}}=A_s\sum_p\left(1-\sum_i x_{ip}\right)^2,
\qquad
P_{\mathrm{once}}=A_o\sum_i\sum_{p<q}x_{ip}x_{iq}.
\]

Selection is implicit: $y_i=\sum_p x_{ip}$. Coverage uses $\sum_{i,p}a_{ri}x_{ip}$. The utility and transition terms from the ordering model apply unchanged. This needs $nK$ logical bits before any slack variables; use it only where exact enumeration can still validate the encoding or where a classical constrained solver supplies the oracle.

### 4.4 The pairwise-state assumption

The transition term assumes that the incremental value of $j$ depends mainly on the immediately preceding test $i$. Real stateful suites may have longer memory, reset boundaries, and non-additive interactions. Measure this assumption:

1. Fit $D_{ij}$ only on historical/training runs.
2. Predict held-out sequence utility as the sum of its pairwise terms.
3. Report out-of-sample residuals and rank correlation with observed utility.
4. Compare with an independent-score-only ablation ($\lambda_D=0$).

If pairwise predictions are weak, do not hide the mismatch with higher penalties. Either add a small number of justified higher-order features and quadratize them with ancillas, or prefer snapshot/state clustering and re-optimize between batches.

## 5. Solver backends

### 5.1 Exact classical solvers

Use two exact references:

- **Exhaustive QUBO enumeration** for very small logical-bit counts. It evaluates all $2^N$ bit strings, catches sign and coefficient errors, and returns every tied optimum.
- **Native constrained optimization** using MILP/MIQP or CP-SAT for larger selection and ordering instances. Solving the native model avoids penalty and quantization artifacts and establishes whether a poor QUBO result is caused by the formulation or the heuristic.

Exact solving is an oracle, not a scalability claim. Record optimality proof status and gap at timeout. Cross-check at least the smallest instances with both exact routes.

### 5.2 Simulated annealing

For a proposed bit flip with energy change $\Delta E$, accept it with

\[
P(\mathrm{accept})=\min\left(1,e^{-\Delta E/T}\right).
\]

Specify the temperature schedule, number of sweeps, number of reads, initial-state policy, seed, and variable-update order. Simulated annealing is the essential always-available BQM baseline, based on the classical method introduced by [Kirkpatrick, Gelatt, and Vecchi 1983](https://doi.org/10.1126/science.220.4598.671).

Do not repeat BootQA's relatively light “100 iterations” baseline and call the comparison settled. Tune SA on a disjoint training set, include multi-start local search or tabu search as an additional strong classical baseline, and publish convergence traces against objective evaluations.

### 5.3 Quantum annealing

Quantum annealing seeks low-energy states of an Ising Hamiltonian by reducing a transverse driver; the foundational numerical study is [Kadowaki and Nishimori 1998](https://doi.org/10.1103/PhysRevE.58.5355). A hardware adapter can consume the same BQM, but hardware introduces coefficient-range scaling, sparse-connectivity embedding, chains, chain breaks, sampling variance, access latency, and queue latency.

BootQA is the key primary result for regression-suite minimization. It used 89, 287, and 1,663 filtered tests from ABB and Google datasets, 100 reads per QPU execution, 10 repetitions, and bootstrap subproblems of at most 160 logical variables. It reported quality close to its SA baseline and lower reported optimization time for the two larger datasets, but embedding time was reported separately and could greatly exceed QPU-access time. It also acknowledged only three datasets, default hardware parameters, access limits, dense embeddings, coefficient scaling, and no quantum-advantage demonstration ([paper](https://arxiv.org/abs/2308.05505)).

Accordingly, a quantum-annealing adapter is a later experiment, not a dependency of the product design.

### 5.4 QAOA simulation

For $N$ QUBO bits, define the cost Hamiltonian

\[
H_C=E\left(\frac{I-Z_1}{2},\ldots,\frac{I-Z_N}{2}\right)
\]

and the usual mixer $H_M=\sum_i X_i$. At depth $p$, prepare

\[
|\psi(\boldsymbol\gamma,\boldsymbol\beta)\rangle
=\prod_{\ell=1}^{p}e^{-i\beta_\ell H_M}e^{-i\gamma_\ell H_C}|+\rangle^{\otimes N},
\]

then use a classical optimizer to minimize

\[
\langle\psi|H_C|\psi\rangle.
\]

This follows the original [Farhi, Goldstone, and Gutmann QAOA proposal](https://arxiv.org/abs/1411.4028). Report depth $p$, circuit gates after decomposition, classical optimizer, starting angles, objective evaluations, shots, seeds, and both the most probable and lowest-energy sampled bit strings.

Use an exact statevector simulator first. It is a correctness and landscape experiment whose memory grows as $O(2^N)$; it is not a faster implementation of the test optimizer. Run both exact-expectation and finite-shot modes. At fixed $p$, compare multiple initializations because the hybrid classical parameter search can dominate results.

For the one-hot ordering model, the ordinary $X$ mixer explores infeasible assignments and relies entirely on penalties to suppress them. A constraint-preserving alternating-operator experiment, initialized in the feasible subspace and using an XY-style mixer, is a meaningful separate variant ([Hadfield et al. 2019](https://doi.org/10.3390/a12020034); [Wang et al. 2020](https://doi.org/10.1103/PhysRevA.101.012320)). Report it separately because it changes the algorithm, state preparation, and circuit cost; it is not merely another solver for the identical penalized QUBO.

The most mature primary QAOA test-optimization result, IGDec-QAOA, used five industrial optimization problems and decomposed them into 7–16-qubit subproblems. Its best reported setting was $p=1,N=7$, and it compared against random search and a genetic algorithm over 30 runs. The real-device result was a small 46-test case study optimized through 7-qubit subproblems. The authors explicitly frame the work as feasibility, not quantum advantage ([paper](https://arxiv.org/abs/2312.15547)). QAOA-TCS is even more preliminary and uses an ideal statevector backend ([paper](https://arxiv.org/abs/2504.18955)).

An adaptive hybrid QAOA framework published at ICST 2026 formulates weighted multi-objective minimization and publishes a reproducibility artifact with batch-wise QAOA, greedy, and SA implementations ([paper DOI](https://doi.org/10.1109/ICST69053.2026.00093); [artifact](https://doi.org/10.5281/zenodo.18897689)). This is useful emerging evidence, but it does not remove the need for exact optima, controlled tuning, and an independent evaluation under the benchmark protocol below.

## 6. Fair benchmark protocol

### 6.1 Questions

Pre-register these questions:

- **RQ1 — Encoding correctness:** Do decoded QUBO optima match native-model optima on oracle-sized instances?
- **RQ2 — Selection quality:** Under equal budgets, which method returns the cheapest feasible corpus and how much required coverage does it retain?
- **RQ3 — Ordering quality:** Does the optimized order improve early held-out information compared with random, total-score, additional-coverage, and pairwise-greedy orders?
- **RQ4 — Search efficiency:** How many objective evaluations and how much end-to-end time are required to reach a fixed target gap?
- **RQ5 — Transition value:** Does adding $D_{ij}$ outperform the otherwise identical $\lambda_D=0$ model on held-out executions?
- **RQ6 — Backend value:** At logical sizes simulatable by QAOA, does any backend improve solution quality or time-to-target after all classical preprocessing and tuning are counted?

### 6.2 Dataset construction

1. Use several open-source systems with machine-runnable regression suites and version history.
2. Partition chronologically: older revisions for feature fitting and tuning, newer revisions for evaluation.
3. Store the coverage matrix, quantized and raw costs, historical outcomes, revision relevance, pairwise transition observations, reset policy, and feature-scaler metadata.
4. Create stratified instances by logical-bit count, coverage density, overlap, cost skew, and observed order sensitivity.
5. Include synthetic instances only for controlled scaling and known optima; report them separately from real suites.
6. Freeze all instance files and hashes before solver evaluation.

Every stateful sequence must begin from the same documented clean state or snapshot. Randomize the order in which solver-produced schedules are evaluated to avoid machine warm-up or temporal drift favoring one method. Repeat observed executions enough times to quantify flakiness.

### 6.3 Compared methods

For selection:

- random feasible construction;
- cost-aware greedy set cover;
- additional-coverage greedy;
- exact native solver;
- exact QUBO enumeration where feasible;
- tuned simulated annealing;
- multi-start local or tabu search;
- QAOA exact-statevector simulation at small $N$.

For ordering:

- random permutation;
- descending independent score $w_i/c_i$;
- additional-coverage greedy;
- pairwise greedy using $D_{ij}$;
- exact assignment/routing model;
- tuned simulated annealing on the identical ordering QUBO;
- QAOA exact-statevector simulation only where the $k^2$ qubit count is practical.

Use the same immutable objective function and decoder for every QUBO backend. Never allow one solver's repair step to use extra domain knowledge unavailable to the others. Report raw and repaired solutions separately.

### 6.4 Budgets and tuning

Use both of these views; neither alone is fair:

- **Equal objective-evaluation budget:** count each evaluated bit string. For QAOA, count every shot-derived sample and every expectation evaluation separately in the raw data.
- **Equal wall-clock budget:** include model construction, embedding or transpilation, parameter optimization, sampling, decoding, and repair. Report remote queue time both included and excluded.

Tune every heuristic on the training instances under the same total tuning budget. Lock parameters before evaluation. For stochastic methods, use at least 30 independent seeds per instance, paired where meaningful. Publish all runs, not only the best run.

For target energy $E_t$, define single-run success probability $\hat p_t$. A standard 99% time-to-solution estimate is

\[
\mathrm{TTS}_{99}=t_{\mathrm{run}}
\frac{\log(1-0.99)}{\log(1-\hat p_t)}.
\]

State whether initialization, programming, embedding/transpilation, classical QAOA optimization, and queue time are included in $t_{\mathrm{run}}$. Avoid extrapolation when $\hat p_t=0$; report a censored result instead.

### 6.5 Metrics

Always report:

- feasibility rate and each constraint's violation magnitude;
- best, median, interquartile range, and 95% confidence interval of objective value;
- normalized optimality gap

  \[
  g=\frac{E-E^*}{\max(1,|E^*|)};
  \]
- selected cardinality, total cost, retained hard-obligation coverage, and redundancy;
- cumulative weighted coverage versus time;
- time to first held-out failure and area under the cumulative detection curve;
- APFD when all tests have equal cost and the assumptions hold; use a cost-aware curve/metric otherwise;
- transition-prediction error and rank correlation on held-out sequences;
- total objective evaluations, solver calls, QAOA shots, circuit depth and gates, annealing reads and sweeps;
- preprocessing, solve, remote-access, decoding, repair, and end-to-end time separately.

APFD was introduced for rate-of-fault-detection comparisons in early prioritization work; its assumptions and use should be documented rather than treating it as a universal score ([Rothermel et al. 1999](https://doi.org/10.1109/ICSM.1999.792604); [Elbaum, Malishevsky, and Rothermel 2002](https://doi.org/10.1109/32.988497)).

Use paired nonparametric comparisons across instances, bootstrap confidence intervals, an effect size, and a multiple-comparison correction. Statistical significance without a practically meaningful gap is not a product improvement.

### 6.6 Reproducibility record

Each run should emit machine-readable JSON containing:

- instance hash and model version;
- raw feature values and normalization version;
- complete QUBO coefficients and matrix convention;
- constraint penalties and their derivation;
- backend and exact dependency versions;
- solver parameters, seed, start state, and stopping reason;
- raw sample set or a content hash plus durable path;
- decoded solution, feasibility, objective components, and timing components;
- exact optimum/bound when available;
- test-execution environment, clean-state identifier, and observed outcomes.

## 7. Interpretation rules and limitations

1. **No quantum-advantage claim.** A simulator result is classical computation. A hardware result on small decomposed instances is feasibility evidence. Rønnow et al. show why speedup depends on the precise comparator and why suboptimal baselines or incomplete accounting can create misleading conclusions ([Rønnow et al., Science 2014](https://doi.org/10.1126/science.1252319); [open preprint](https://arxiv.org/abs/1401.2910)).
2. **One-hot ordering is expensive.** Ordering $k$ tests requires $k^2$ logical bits. Exact statevector simulation then stores $2^{k^2}$ amplitudes. Even ordering five tests already needs 25 logical qubits before ancillas.
3. **Dense objectives are unfriendly to sparse hardware.** Pairwise redundancy and transition matrices can make the logical graph dense, increasing embedding chains and coefficient compression for annealers and two-qubit gates for QAOA.
4. **Penalties change the search landscape.** A penalty can be mathematically sufficient yet numerically harmful. Feasibility must be reported independently, and exact small-instance validation is mandatory.
5. **Historical effectiveness can drift.** Failure history, timings, and transition scores may not transfer to later revisions. Chronological evaluation is required.
6. **Coverage is a proxy.** Preserving statement or branch coverage does not prove preservation of regression-detection power. Report held-out outcomes as well as structural coverage.
7. **Pairwise transitions may be insufficient.** Longer state histories, reset behavior, and concurrency can violate the Markov assumption in $D_{ij}$.
8. **Decomposition changes the algorithm.** BootQA, IGDec-QAOA, and QAOA-TCS combine quantum or quantum-inspired subproblem solving with classical decomposition or clustering. Performance cannot be attributed to the quantum subroutine without ablations.
9. **Published comparisons are not yet conclusive.** BootQA used three datasets and a modest SA configuration; IGDec-QAOA used small QAOA subproblems and GA/random baselines; QAOA-TCS is an ideal-simulator preliminary study; SelectQA compared execution across heterogeneous platforms; the adaptive 2026 QAOA study is too recent for independent replication evidence.
10. **Weighted sums expose policy choices.** Different weights can select different Pareto-optimal corpora. Publish sensitivity analyses and, where user choice matters, expose a small Pareto set instead of a single allegedly universal optimum.

## 8. Recommended implementation sequence

1. Implement immutable selection and ordering instance schemas plus a canonical objective evaluator.
2. Implement native exact models and tiny exhaustive-QUBO checks.
3. Implement the selection QUBO, constraint audit, and coefficient-convention tests.
4. Implement the two-stage ordering QUBO and its pairwise-score ablation.
5. Add tuned simulated annealing and strong classical greedy/local-search baselines.
6. Run oracle-sized and real-suite benchmarks; revise the formulation if QUBO optima do not match native optima.
7. Add exact-statevector QAOA for small logical sizes with fixed depth and multi-start parameter optimization.
8. Only after the benchmark harness is stable, consider optional noisy simulation or remote annealing/hardware adapters.

The decision gate for retaining QAOA is not “does it run?” It is whether the backend yields useful, reproducible information beyond exact and classical heuristic baselines at the sizes it can actually process. The product remains complete and useful if the answer is no.

## 9. Evidence gaps

- No reviewed primary paper was found that evaluates a one-hot QUBO with asymmetric pairwise transition scores for **ordering stateful classical-software tests**. This document's ordering formulation is derived from permutation/routing QUBOs and must be treated as a hypothesis.
- No directly relevant study establishes asymptotic or practical quantum advantage for regression-test selection, minimization, or prioritization.
- Existing quantum test-optimization papers use different objectives, decompositions, datasets, baselines, and timing boundaries, preventing a reliable cross-paper ranking.
- Public evidence is thin on exact-optimum gaps for realistic regression suites; several studies compare only against heuristic baselines or a posteriori Pareto fronts.
- There is insufficient evidence that historical pairwise test transitions generalize across revisions. A new chronological dataset and ablation study are needed.
- Penalty-weight guidance is general rather than specific to test selection and stateful ordering. Instance-dependent coefficient scaling needs empirical characterization.
- Statevector QAOA can validate only small logical models, especially with the $k^2$ one-hot ordering encoding. Tensor-network simulation may extend some sparse cases but would be a different backend with different biases.
- The adaptive 2026 QAOA minimization study adds an artifact and classical fallbacks, but no independent replication or broader cross-project evaluation was located.
- Remote quantum timing is often reported without a uniform accounting of queueing, embedding/transpilation, repeated reads/shots, and classical optimizer work. A credible benchmark must publish all components.

## Primary references

- G. Rothermel, R. H. Untch, C. Chu, and M. J. Harrold, “Test Case Prioritization: An Empirical Study,” ICSM 1999. [DOI](https://doi.org/10.1109/ICSM.1999.792604) · [author-hosted PDF](https://courses.cs.umbc.edu/undergraduate/345/spring12/mitchell/readings/testCasePrioritization-AnEmpiricalStudy.pdf)
- S. Elbaum, A. G. Malishevsky, and G. Rothermel, “Test Case Prioritization: A Family of Empirical Studies,” IEEE TSE 28(2), 2002. [DOI](https://doi.org/10.1109/32.988497) · [repository record](https://digitalcommons.unl.edu/csearticles/8/)
- Y. Ledru, A. Petrenko, S. Boroday, and N. Mandran, “Prioritizing Test Cases with String Distances,” Automated Software Engineering 19, 2012. [DOI](https://doi.org/10.1007/s10515-011-0093-0)
- S. Yoo and M. Harman, “Using Hybrid Algorithm for Pareto Efficient Multi-objective Test Suite Minimisation,” Journal of Systems and Software 83(4), 2010. [DOI](https://doi.org/10.1016/j.jss.2009.11.706)
- F. Glover, G. Kochenberger, and Y. Du, “Quantum Bridge Analytics I: A Tutorial on Formulating and Using QUBO Models,” 4OR 17, 2019. [DOI](https://doi.org/10.1007/s10288-019-00424-y) · [open preprint](https://arxiv.org/abs/1811.11538)
- A. Lucas, “Ising Formulations of Many NP Problems,” Frontiers in Physics 2, 2014. [DOI/full text](https://doi.org/10.3389/fphy.2014.00005)
- M. Ayodele, “Penalty Weights in QUBO Formulations: Permutation Problems,” EvoCOP 2022. [Open preprint](https://arxiv.org/abs/2206.11040)
- S. Kirkpatrick, C. D. Gelatt Jr., and M. P. Vecchi, “Optimization by Simulated Annealing,” Science 220, 1983. [DOI](https://doi.org/10.1126/science.220.4598.671)
- T. Kadowaki and H. Nishimori, “Quantum Annealing in the Transverse Ising Model,” Physical Review E 58, 1998. [DOI/full text](https://doi.org/10.1103/PhysRevE.58.5355)
- E. Farhi, J. Goldstone, and S. Gutmann, “A Quantum Approximate Optimization Algorithm,” 2014. [Open preprint](https://arxiv.org/abs/1411.4028)
- S. Hadfield et al., “From the Quantum Approximate Optimization Algorithm to a Quantum Alternating Operator Ansatz,” Algorithms 12(2), 2019. [DOI/full text](https://doi.org/10.3390/a12020034)
- Z. Wang, N. C. Rubin, J. M. Dominy, and E. G. Rieffel, “XY-Mixers: Analytical and Numerical Results for QAOA,” Physical Review A 101, 2020. [DOI](https://doi.org/10.1103/PhysRevA.101.012320) · [open preprint](https://arxiv.org/abs/1904.09314)
- X. Wang, A. Muqeet, T. Yue, S. Ali, and P. Arcaini, “Test Case Minimization with Quantum Annealers,” ACM TOSEM 34(1), 2024. [DOI](https://doi.org/10.1145/3680467) · [open preprint](https://arxiv.org/abs/2308.05505)
- X. Wang, S. Ali, T. Yue, and P. Arcaini, “Quantum Approximate Optimization Algorithm for Test Case Optimization,” IEEE TSE 50(12), 2024. [DOI](https://doi.org/10.1109/TSE.2024.3479421) · [open preprint](https://arxiv.org/abs/2312.15547)
- A. Trovato, M. De Stefano, F. Pecorelli, D. Di Nucci, and A. De Lucia, “Reformulating Regression Test Suite Optimization Using Quantum Annealing—An Empirical Study,” STTT 26, 2024. [DOI](https://doi.org/10.1007/s10009-024-00775-w) · [open preprint](https://arxiv.org/abs/2411.15963)
- A. Trovato, M. Beseda, and D. Di Nucci, “A Preliminary Investigation on the Usage of Quantum Approximate Optimization Algorithms for Test Case Selection,” EASE Companion 2025. [DOI](https://doi.org/10.1145/3727967.3756821) · [open preprint](https://arxiv.org/abs/2504.18955)
- L. Sharma, K. Sharma, and A. Kumar, “An Adaptive Hybrid Quantum-Classical Framework for Test Suite Minimization via Quantum Approximate Optimization Algorithm,” ICST 2026. [DOI](https://doi.org/10.1109/ICST69053.2026.00093) · [reproducibility artifact](https://doi.org/10.5281/zenodo.18897689)
- T. F. Rønnow et al., “Defining and Detecting Quantum Speedup,” Science 345, 2014. [DOI](https://doi.org/10.1126/science.1252319) · [open preprint](https://arxiv.org/abs/1401.2910)
