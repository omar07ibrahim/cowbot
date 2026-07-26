# Calibrated mechanism-monitor contract

COWBOT asks a narrower question than a generic anomaly detector:

> Which fitted local metric predictor stopped behaving like its healthy
> history,
> after accounting for the lagged parents that an operator says can influence
> it?

The graph is an operational hypothesis. A residual alarm is evidence that the
fitted conditional predictor failed, not proof that a physical mechanism
changed. COWBOT does not discover a causal graph or identify causality. A wrong
or incomplete graph can produce a wrong triage result.

## Partitions

For the default replay, samples are divided by index:

- fit: `[1, 120)`, with the exact start adjusted to the largest required lag;
- calibration: `[120, 200)`;
- monitoring: `[200, end)`.

The target-index partitions are disjoint. Lag context intentionally crosses a
boundary: calibration target 120 may read fit sample 119, and monitoring target
200 may read calibration sample 199. No calibration or monitoring target is
used to fit a model. The simulator's separate truth file is never passed to
`monitor_stream`.

## Local predictor

For metric \(j\), the feature vector contains:

1. the metric's own value at \(t-1\);
2. each declared parent value at the edge's exact lag.

The autoregressive feature is model state, not a self-edge in the operator
graph. Self-edges remain invalid because the graph records cross-metric
dependency hypotheses.

Before fitting, every target and feature is normalized by its declared metric
span. Features are then standardized using fit-only means and population
standard deviations. A column whose computed population standard deviation is
exactly zero receives a scale of one and therefore becomes a zero standardized
column. The target is centered, and coefficients solve

\[
  (Z^\top Z + \lambda n I)\beta = Z^\top(y-\bar{y})
\]

with a bounded Cholesky solver. The default \(\lambda\) is \(10^{-6}\). This is
a small linear conditional model, not a claim that the service dynamics are
linear.

## Nonconformity and calibration

Training residual scale is the normal-consistency form of median absolute
deviation:

\[
  s = 1.4826022185\ \mathrm{median}(|r_i-\mathrm{median}(r)|).
\]

If MAD collapses, the implementation falls back to residual RMS and then a
`1e-12` floor in normalized metric-span units. This positive scale is useful
for numerical reporting, but it does not create conformal calibration: using
the same scale for calibration and monitoring does not change score ranks. A
monitored residual receives score

\[
  a_t = \frac{|y_t-\hat{y}_t|}{s}.
\]

Given \(m\) calibration scores, the conservative rank is

\[
  p_t =
  \frac{1 + |\{a_i^{cal}: a_i^{cal} \ge a_t\}|}{m+1}.
\]

Using `>=` keeps ties on the conservative side. The minimum possible default
p-value is therefore \(1/81\), not zero.

## Sequential evidence

For a fixed \(\epsilon\in(0,1)\), each p-value is converted to the power factor

\[
  e_t = \epsilon p_t^{\epsilon-1}.
\]

COWBOT accumulates `log(e_t)` and raises the first local alarm when the product
crosses `alarm_wealth` (100 by default).

This repository calls the result **power wealth**, not an anytime-valid false
alarm guarantee. Conditional on fixed fit data, if the \(m\) calibration scores
and one fresh test score are exchangeable, the tie-conservative rank is
marginally super-uniform. Reusing the same calibration set over serial scores
does not establish that the p-value sequence is conditionally super-uniform.
Telemetry is serially dependent, and a supplied graph may be misspecified.
Those facts do not justify treating wealth 100 as a 1% false-alarm probability
or an operational SLA probability.

The construction is related to conformal test martingales described by
[Vovk et al. (2021)](https://proceedings.mlr.press/v152/vovk21b.html), but
COWBOT's fixed shared calibration and time-series setting retain the
limitations above. The local-mechanism framing is related to causal anomaly
localization by
[Yang, Zhang, and Hoi (2022)](https://arxiv.org/abs/2206.15033); this project is
not a reproduction of that model.

## Root-cause ranking

Only metrics with a local alarm are candidates. Triage is computed after the
bounded replay; it is not an as-of online root decision. For every ancestor to
descendant pair, COWBOT computes the minimum sum of edge lags. A downstream
candidate is suppressed only when an alarmed ancestor occurred early enough to
reach it through that path. Compatible descendants support an unsuppressed
candidate only when their alarm time respects the same lag constraint.

Remaining origin candidates are ranked deterministically by alarm index,
compatible downstream-alarm count, peak log power wealth, and metric name.
Suppressed candidates and all compatible ancestors remain in the report; they
are not silently discarded.

This ordering distinguishes a plausible origin from propagated symptoms in the
default crafted replay. The healthy fit does not exercise every nonlinear
simulator branch, so downstream predictor alarms can occur even when their
simulator equations did not change. The ordering is not a universal root-cause
identification guarantee.

## Committed fixture boundary

The default simulator fixture is a single deterministic worked example, not a
benchmark. With the default seed 20260725 and onset index 220, its committed
regression contract is:

| metric | first local alarm |
| --- | ---: |
| `request_rate` | none |
| `worker_cpu` | 224 |
| `queue_depth` | 225 |
| `latency_ms` | 227 |
| `error_rate` | 229 |

`worker_cpu` has the minimum attainable p-value, \(1/81\), at indices
220 through 224 and is the first ranked origin candidate. This result is
specific to the fixture and configuration above.

The test suite also freezes a deliberately inconvenient case. With seed 13,
`queue_depth` raises at index 218, before the injected onset at 220, and is
ranked first. COWBOT keeps that counterexample instead of tuning it away. No
multi-seed detection-rate, universal localization, or production false-alarm
claim follows from the simulator.

## Explicit boundaries

- Fit and calibration data must represent the intended healthy regime.
- Missing values, dynamic schemas, and online model updates are unsupported.
- All features are lagged; contemporaneous edges are unsupported.
- The general stream schema permits more edges than the current monitor. A
  local predictor is rejected if self-history plus declared parent-lag features
  exceeds 65.
- The current implementation keeps observations in memory, caps a stream at
  one million samples, and rejects reports above two million node
  observations. Across a monitor run it permits at most two million fit
  feature cells, 40 million normal-equation products, and two million
  calibration feature cells. The lower-level ridge solver separately permits
  at most one million fit cells and 20 million normal-equation products per
  fit. These budgets are checked before copying rows or fitting models.
- Threshold tuning on the included incident would contaminate its evaluation.
- Benchmark, latency, throughput, and broad detection-rate claims are outside
  the current slice.
