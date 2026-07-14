#!/usr/bin/env node

const { spawnSync } = require('child_process');
const http = require('http');

const ORDERED_LEVELS = ['info', 'low', 'moderate', 'high', 'critical'];

const PROXY_TYPES = {
	local: '127.0.0.1',
	pipe: 'host.docker.internal',
};

const SEVERITY_MAP = {
	info: 'LOW',
	low: 'LOW',
	moderate: 'MEDIUM',
	high: 'HIGH',
	critical: 'CRITICAL',
};

class Config {
	constructor() {
		this.bitbucket = {
			branch: process.env.BITBUCKET_BRANCH,
			commit: process.env.BITBUCKET_COMMIT,
			owner: process.env.BITBUCKET_REPO_OWNER,
			slug: process.env.BITBUCKET_REPO_SLUG,
		};

		this.reportName = process.env.BPR_NAME || 'Security: npm audit';
		this.reportId = process.env.BPR_ID || 'npmaudit';
		this.proxyHost = PROXY_TYPES[process.env.BPR_PROXY] || PROXY_TYPES.local;
		this.auditLevel = process.env.BPR_LEVEL || 'high';
		this.auditAnnotationLevel = process.env.BPR_LOG;
		this.maxBufferSize = parseInt(process.env.BPR_MAX_BUFFER_SIZE, 10) || 1024 * 1024 * 10;

		this._validate();
	}

	_validate() {
		const missingEnvVars = Object.entries(this.bitbucket)
			.filter(([_, value]) => !value)
			.map(([key]) => `BITBUCKET_${key.toUpperCase()}`);

		if (missingEnvVars.length > 0) {
			throw new Error(`Missing required Bitbucket environment variables: ${missingEnvVars.join(', ')}`);
		}

		if (!ORDERED_LEVELS.includes(this.auditLevel)) {
			throw new Error(`Unsupported audit level: "${this.auditLevel}". Must be one of: ${ORDERED_LEVELS.join(', ')}`);
		}

		if (!this.proxyHost) {
			throw new Error('Unsupported proxy configuration.');
		}
	}
}

class AuditRunner {
	static run(packageManager, maxBuffer) {
		const { stderr, stdout, error } = spawnSync('pnpm', ['audit', '--json'], { maxBuffer });

		if (error) {
			throw new Error(`Failed to start the process "pnpm": ${error.message}`);
		}

		const stderrStr = stderr ? stderr.toString().trim() : '';
		const stdoutStr = stdout ? stdout.toString().trim() : '';

		// Fail only if we have no output data but explicitly received error logs
		if (!stdoutStr && stderrStr) {
			throw new Error(`Could not execute the audit command. Error output:\n${stderrStr}`);
		}

		try {
			return JSON.parse(stdoutStr);
		} catch (err) {
			const context = stderrStr ? `\n\nAdditional stderr output:\n${stderrStr}` : '';
			throw new Error(`Error parsing JSON output from pnpm audit: ${err.message}${context}`);
		}
	}
}

class AuditParser {
	static getHighestLevelIndex(auditData) {
		const vulnerabilities = auditData?.metadata?.vulnerabilities;
		if (!vulnerabilities) return -1;

		return ORDERED_LEVELS.reduce((maxIdx, level, idx) => {
			return vulnerabilities[level] ? idx : maxIdx;
		}, -1);
	}

	static getTotalDependencies(auditData) {
		if (!auditData?.metadata) return 0;

		return auditData.metadata.dependencies;
	}

	static extractAnnotations(auditData, config) {
		const annotations = [];

		const shouldAddAnnotation = (severity) => {
			if (!config.auditAnnotationLevel) return true;
			return ORDERED_LEVELS.indexOf(severity) >= ORDERED_LEVELS.indexOf(config.auditAnnotationLevel);
		};


		for (const [id, advisory] of Object.entries(auditData.advisories)) {
			if (!shouldAddAnnotation(advisory.severity)) continue;

			const paths = '- ' + advisory.findings[0]?.paths.join('\n- ');

			annotations.push({
				id: id.replace(/\//g, '-'),
				summary: `${advisory.module_name}: ${advisory.title}`,
				details: `Vulnerable version: ${advisory.vulnerable_versions}\nFixed in: ${advisory.patched_versions}\nFound in:\n${paths}`,
				link: advisory.url,
				path: "package.json",
				line: 1,
				severity: SEVERITY_MAP[advisory.severity] || 'LOW',
			});
		}

		// Bitbucket Report API limits a single report to 1000 annotations
		return annotations.slice(0, 1000);
	}
}

class BitbucketClient {
	constructor(config) {
		this.config = config;
		this.baseUrl = [
			'https://api.bitbucket.org/2.0/repositories/',
			config.bitbucket.owner,
			'/',
			config.bitbucket.slug,
			'/commit/',
			config.bitbucket.commit,
			'/reports/',
			config.reportId,
		].join('');
	}

	async _request(endpointPath, payload) {
		return new Promise((resolve, reject) => {
			const options = {
				host: this.config.proxyHost,
				port: 29418,
				path: endpointPath,
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
			};

			const req = http.request(options, (res) => {
				let responseBody = '';
				res.setEncoding('utf8');
				res.on('data', chunk => responseBody += chunk);
				res.on('end', () => {
					if (res.statusCode !== 200) {
						reject(new Error(`API responded with ${res.statusCode}: ${responseBody}`));
					} else {
						resolve();
					}
				});
			});

			req.on('error', (err) => reject(new Error(`Network request failed: ${err.message}`)));
			req.write(JSON.stringify(payload));
			req.end();
		});
	}

	async pushMainReport(reportData) {
		await this._request(this.baseUrl, reportData);
	}

	async pushAnnotation(annotation) {
		const endpoint = `${this.baseUrl}/annotations/${this.config.reportId}-${annotation.id}`;
		await this._request(endpoint, {
			annotation_type: 'VULNERABILITY',
			summary: annotation.summary,
			details: annotation.details,
			link: annotation.link,
			severity: annotation.severity,
		});
	}
}

async function main() {
	const startTime = Date.now();
	console.log('Initializing dependency vulnerability scan...');

	try {
		const config = new Config();
		console.log(`Running audit via ${config.packageManager}...`);

		const auditData = AuditRunner.run(config.packageManager, config.maxBufferSize);
		const bitbucketClient = new BitbucketClient(config);

		const highestLevelIndex = AuditParser.getHighestLevelIndex(auditData);
		const isSafeToMerge = highestLevelIndex <= ORDERED_LEVELS.indexOf(config.auditLevel);
		const totalDeps = AuditParser.getTotalDependencies(auditData);

		console.log(`Audit run complete. Safe to merge? -> ${isSafeToMerge ? 'PASSED' : 'FAILED'}`);
		console.log('Publishing build report summary to Bitbucket...');

		const durationSeconds = Math.round((Date.now() - startTime) / 1000);

		await bitbucketClient.pushMainReport({
			title: config.reportName,
			details: 'Vulnerability scan results of package dependencies.',
			report_type: 'SECURITY',
			reporter: "pnpm",
			result: isSafeToMerge ? 'PASSED' : 'FAILED',
			data: [
				{
					title: 'Duration (seconds)',
					type: 'DURATION',
					value: durationSeconds,
				},
				{
					title: 'Dependencies',
					type: 'NUMBER',
					value: totalDeps,
				},
				{
					title: 'Safe to merge?',
					type: 'BOOLEAN',
					value: isSafeToMerge,
				},
			],
		});

		console.log('Parsing code annotations...');
		const annotations = AuditParser.extractAnnotations(auditData, config);

		if (annotations.length > 0) {
			console.log(`Publishing ${annotations.length} annotation(s) to Bitbucket...`);
			for (const annotation of annotations) {
				await bitbucketClient.pushAnnotation(annotation);
			}
		}

		console.log('Vulnerability integration report finished successfully.');

		if (isSafeToMerge) {
			process.exit(0);
		} else {
			process.exit(1);
		}

	} catch (error) {
		console.error('\x1b[31mFatal Execution Error:\x1b[0m', error.message);
		process.exit(1);
	}
}

main();
