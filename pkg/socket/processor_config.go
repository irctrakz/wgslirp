package socket

import (
	"fmt"
	"github.com/irctrakz/wgslirp/internal/envconfig"
)

// ProcessorConfig configures the optional library worker pool. The executable
// uses inline delivery, so these controls do not apply to its production path.
type ProcessorConfig struct{ Workers, QueueCapacity int }

func DefaultProcessorConfig() ProcessorConfig { return ProcessorConfig{4, 1000} }
func (c ProcessorConfig) Validate() error {
	if c.Workers < 1 || c.Workers > 256 {
		return fmt.Errorf("PROCESSOR_WORKERS must be between 1 and 256")
	}
	if c.QueueCapacity < 1 || c.QueueCapacity > 65536 {
		return fmt.Errorf("PROCESSOR_QUEUE_CAP must be between 1 and 65536")
	}
	return nil
}
func ProcessorConfigFromEnv(base ProcessorConfig, lookup func(string) (string, bool)) (ProcessorConfig, error) {
	r := envconfig.Reader{Lookup: lookup}
	c := ProcessorConfig{r.Int("PROCESSOR_WORKERS", base.Workers, 1, 256), r.Int("PROCESSOR_QUEUE_CAP", base.QueueCapacity, 1, 65536)}
	if r.Err != nil {
		return c, r.Err
	}
	return c, c.Validate()
}
