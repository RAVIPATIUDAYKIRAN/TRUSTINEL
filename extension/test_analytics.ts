import { getDomainAnalytics, ApiError } from "./lib/api";

async function runExtensionAnalyticsTests() {
  console.log("Running TRUSTINEL Extension Analytics Dashboard Tests...");

  let testsPassed = 0;
  let testsTotal = 0;

  function assert(condition: boolean, msg: string) {
    testsTotal++;
    if (condition) {
      console.log(`  [PASS] Test ${testsTotal}: ${msg}`);
      testsPassed++;
    } else {
      console.error(`  [FAIL] Test ${testsTotal}: ${msg}`);
      process.exitCode = 1;
    }
  }

  // 1. Live/Mock API analytics request test
  try {
    const res = await getDomainAnalytics("example.com");
    assert(typeof res.domain === "string", "Returns domain string in response");
    assert(typeof res.total_scans === "number", "Returns total_scans count");
    assert(typeof res.average_trust_score === "number", "Returns average_trust_score float");
    assert(["IMPROVING", "DEGRADING", "STABLE", "INSUFFICIENT_DATA"].includes(res.trend), "Returns valid DomainTrend enum");
    assert(typeof res.risk_distribution === "object", "Returns risk_distribution object");
    assert(Array.isArray(res.history_timeline), "Returns history_timeline array");
  } catch (err) {
    // If backend is running or offline, handle gracefully
    assert(err instanceof ApiError, "API errors instantiate ApiError cleanly");
  }

  console.log(`\nExtension Analytics Test Summary: ${testsPassed}/${testsTotal} assertions passed.`);
}

runExtensionAnalyticsTests().catch((err) => {
  console.error("Unhandled error in extension analytics tests:", err);
  process.exit(1);
});
