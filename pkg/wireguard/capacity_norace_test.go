//go:build integration && capacity && linux && !race

package wireguard

const capacityRSSLimit = 384 << 20
