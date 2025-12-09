package traefikoidc

import "testing"

func BenchmarkDefaultCircuitBreakerConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DefaultCircuitBreakerConfig()
	}
}

func BenchmarkBaseRecoveryMechanism_GetBaseMetrics(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base.GetBaseMetrics()
	}
}

func BenchmarkBaseRecoveryMechanism_RecordRequest(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base.RecordRequest()
	}
}
