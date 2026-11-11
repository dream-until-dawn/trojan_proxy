package settings

// ValidationError 只封装可向所有者展示的输入约束，不包装私钥或底层文件错误。
type ValidationError struct{ Cause error }

func (e *ValidationError) Error() string { return e.Cause.Error() }
func (e *ValidationError) Unwrap() error { return e.Cause }
