//go:build integration && capacity && linux && race

package wireguard

// Race instrumentation maintains memory outside the sampled Go heap. The
// 256-flow profile retains the ordinary heap limit and gets a separate RSS cap.
const capacityRSSLimit = 512 << 20
