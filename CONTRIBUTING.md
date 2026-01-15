# Contributing to Research-Projects

Thank you for your interest in contributing! This document provides guidelines for contributing to the Research-Projects repository.

## How to Contribute

### Reporting Issues
- Check existing issues to avoid duplicates
- Provide clear descriptions of the problem
- Include steps to reproduce (if applicable)
- Specify your environment (OS, ESP-IDF version, hardware)

### Submitting Changes
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request with a description of changes

### Pull Request Guidelines
- Reference any related issues
- Provide a clear description of what changed and why
- Ensure code follows the existing style
- Test on target hardware when applicable
- Update documentation if needed

## Code Standards

- Keep changes focused and minimal
- Follow existing code style in each project
- Add comments only for complex logic
- Test before submitting

## Project-Specific Notes

### PwnPower
- Changes to web UI require running `python interface/convert_multi.py` to regenerate C arrays
- Test on ESP32-C3 hardware
- Update CHANGELOG.md with your changes

### Hackers-Night-Light
- Hardware-specific code should be clearly documented
- Test flashing process with target devices
- Update device-specific READMEs if adding support

## Questions?

Open an issue for questions or discussions about contributing.
