// Package storage abstracts the object-store backend (Cloudflare R2 or any
// S3-compatible service).
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
)

// Object is a stored object's metadata.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ErrPreconditionFailed is returned by PutIf when the condition does not
// hold (the object exists, or its ETag changed). The loser of a race
// simply re-reads and retries or reports — nothing is left behind, which
// is why conditional writes are used here instead of locks.
var ErrPreconditionFailed = errors.New("precondition failed")

// ErrConditionalUnsupported is returned by PutIf when the backend cannot
// enforce conditional writes; callers fall back to an unconditional Put
// (the pre-conditional-write behavior).
var ErrConditionalUnsupported = errors.New("backend does not support conditional writes")

// Storage is the minimal object-store interface the helper needs.
type Storage interface {
	List(ctx context.Context, prefix string) ([]Object, error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Put(ctx context.Context, key string, body io.Reader, size int64) error
	// PutIf writes key only when a precondition holds: with ifMatch == ""
	// the object must not exist (create-only); otherwise the stored
	// object's ETag must equal ifMatch (compare-and-swap).
	PutIf(ctx context.Context, key string, body io.Reader, size int64, ifMatch string) error
	// ETag returns the current ETag of key ("" with nil error when the
	// object does not exist).
	ETag(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}

// S3Storage implements Storage on top of the AWS SDK v2 S3 client, which
// speaks to R2, AWS S3, MinIO, and other compatible services.
type S3Storage struct {
	client *s3.Client
	bucket string
}

// New builds an S3Storage from the resolved helper configuration.
// Credentials must be explicit (env vars or the credential store); the
// AWS default chain — ~/.aws/credentials, instance roles — is
// deliberately never consulted.
func New(ctx context.Context, cfg *config.Config) (*S3Storage, error) {
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("no S3 credentials configured for bucket %q; "+
			"run `git-remote-s3vault setup`, or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY", cfg.Bucket)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)),
		awsconfig.WithSharedConfigFiles(nil),
		awsconfig.WithSharedCredentialsFiles(nil),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})
	return &S3Storage{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3Storage) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", prefix, err)
		}
		for _, o := range page.Contents {
			out = append(out, Object{
				Key:          aws.ToString(o.Key),
				Size:         aws.ToInt64(o.Size),
				LastModified: aws.ToTime(o.LastModified),
			})
		}
	}
	return out, nil
}

func (s *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("getting %s: %w", key, err)
	}
	return resp.Body, nil
}

func (s *S3Storage) Put(ctx context.Context, key string, body io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("putting %s: %w", key, err)
	}
	return nil
}

func (s *S3Storage) PutIf(ctx context.Context, key string, body io.Reader, size int64, ifMatch string) error {
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	}
	if ifMatch == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(ifMatch)
	}
	_, err := s.client.PutObject(ctx, in)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "PreconditionFailed", "ConditionalRequestConflict":
				return fmt.Errorf("putting %s: %w", key, ErrPreconditionFailed)
			case "NotImplemented":
				return ErrConditionalUnsupported
			}
		}
		return fmt.Errorf("putting %s: %w", key, err)
	}
	return nil
}

func (s *S3Storage) ETag(ctx context.Context, key string) (string, error) {
	resp, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nf *types.NotFound
		if errors.As(err, &nf) {
			return "", nil
		}
		return "", fmt.Errorf("heading %s: %w", key, err)
	}
	return aws.ToString(resp.ETag), nil
}

func (s *S3Storage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("deleting %s: %w", key, err)
	}
	return nil
}

func (s *S3Storage) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nf *types.NotFound
		if errors.As(err, &nf) {
			return false, nil
		}
		return false, fmt.Errorf("heading %s: %w", key, err)
	}
	return true, nil
}
