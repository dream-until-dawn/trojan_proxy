package subscription

import "context"

// Service 的令牌仅允许读取本机VPN配置，不能创建管理员会话或访问其他资源。
type Service struct {
	store  *Store
	owner  func(context.Context) (string, error)
	export func(context.Context) ([]byte, error)
	budget chan struct{}
}

// New 接受当前管理员代次和已应用VPN导出器，不接受远程订阅地址。
func New(store *Store, owner func(context.Context) (string, error), export func(context.Context) ([]byte, error)) *Service {
	return &Service{store: store, owner: owner, export: export, budget: make(chan struct{}, 2)}
}
func (s *Service) binding(ctx context.Context) (string, error) {
	value, err := s.owner(ctx)
	if err != nil || !validOwner(value) {
		return "", ErrUnavailable
	}
	return value, nil
}

// Create 产生一次性展示的链接令牌；HTTP层另行要求近期MFA。
func (s *Service) Create(ctx context.Context, name string) (Record, string, error) {
	owner, err := s.binding(ctx)
	if err != nil {
		return Record{}, "", err
	}
	return s.store.Create(ctx, owner, name)
}

// List 不读取或重建原始令牌。
func (s *Service) List(ctx context.Context) ([]Record, error) {
	owner, err := s.binding(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.List(ctx, owner)
}

// Revoke 撤销指定设备后，后续获取立即拒绝。
func (s *Service) Revoke(ctx context.Context, id string) error {
	owner, err := s.binding(ctx)
	if err != nil {
		return err
	}
	return s.store.Revoke(ctx, owner, id)
}

// Fetch 限制并发并在导出后复验，避免排队期间撤销的授权继续得到秘密。
func (s *Service) Fetch(ctx context.Context, token string) ([]byte, error) {
	if !validToken(token) {
		return nil, ErrDenied
	}
	select {
	case s.budget <- struct{}{}:
		defer func() { <-s.budget }()
	default:
		return nil, ErrLimit
	}
	owner, err := s.binding(ctx)
	if err != nil {
		return nil, err
	}
	if err = s.store.Validate(ctx, owner, token); err != nil {
		return nil, err
	}
	body, err := s.export(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	current, err := s.binding(ctx)
	if err != nil {
		return nil, err
	}
	if current != owner {
		return nil, ErrDenied
	}
	if err = s.store.Validate(ctx, owner, token); err != nil {
		return nil, err
	}
	return body, nil
}
