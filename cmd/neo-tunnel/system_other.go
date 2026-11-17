//go:build !linux

package main

import "errors"

type sampler struct{ config AgentConfig }

func (s *sampler) sample() (*Reading, error) {
	return nil, errors.New("resource collection requires Linux cgroup v2")
}
