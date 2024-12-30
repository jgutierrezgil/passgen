# test/password_generator_test.rb
require 'minitest/autorun'
require_relative '../lib/password_generator'

class PasswordGeneratorTest < Minitest::Test
  def setup
    @generator = PasswordGenerator.new
    @analyzer = PasswordStrengthAnalyzer.new
  end

  def test_generates_password_with_correct_length
    length = 16
    result = @generator.generate!(length)
    assert_equal length, result[:password].length
  end

  def test_generates_password_with_special_chars_when_requested
    result = @generator.generate!(12, include_special: true)
    # Modificamos esta línea para usar los caracteres especiales exactos que definimos
    has_special = result[:password].chars.any? { |char| PasswordGenerator::SPECIAL_CHARS.include?(char) }
    assert has_special, "Password should contain at least one special character"
  end

  def test_generates_password_without_special_chars_when_not_requested
    result = @generator.generate!(12, include_special: false)
    has_special = result[:password].chars.any? { |char| PasswordGenerator::SPECIAL_CHARS.include?(char) }
    refute has_special, "Password should not contain special characters"
  end

  def test_raises_error_for_short_password
    assert_raises(ArgumentError) do
      @generator.generate!(7)
    end
  end

  def test_raises_error_for_long_password
    assert_raises(ArgumentError) do
      @generator.generate!(101)
    end
  end

  def test_password_strength_analysis_weak
    result = @analyzer.analyze('abc123')
    assert_equal :weak, result[:strength]
  end

  def test_password_strength_analysis_strong
    result = @analyzer.analyze('P@ssw0rd123!')
    assert_equal :strong, result[:strength]
  end

  def test_detects_common_patterns
    result = @analyzer.analyze('abc123456')
    assert result[:details][:has_common_patterns]
  end
end