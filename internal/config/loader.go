package config

import env "github.com/Netflix/go-env"

func Load() (Environment, error) {
	var cfg Environment
	if _, err := env.UnmarshalFromEnviron(&cfg); err != nil {
		return Environment{}, err
	}

	return cfg, nil
}
