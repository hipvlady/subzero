"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

MCP Dynamic Capability Discovery
Runtime capability negotiation and discovery for AI agents

Features:
- Dynamic capability registration
- Runtime capability discovery
- Multi-step workflow support
- Complex operation abstraction
- Capability versioning
- Negotiation protocol
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

import numpy as np


class CapabilityType(str, Enum):
    """Types of MCP capabilities"""

    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"
    WORKFLOW = "workflow"


class OperationComplexity(str, Enum):
    """Operation complexity levels"""

    SIMPLE = "simple"  # Single step
    MODERATE = "moderate"  # 2-5 steps
    COMPLEX = "complex"  # 5+ steps or branching
    WORKFLOW = "workflow"  # Multi-agent coordination


@dataclass
class CapabilitySchema:
    """Schema definition for a capability"""

    name: str
    type: CapabilityType
    description: str
    input_schema: dict
    output_schema: dict
    complexity: OperationComplexity = OperationComplexity.SIMPLE
    version: str = "1.0.0"
    requires: list[str] = field(default_factory=list)  # Dependencies
    tags: set[str] = field(default_factory=set)


@dataclass
class WorkflowStep:
    """Single step in a multi-step workflow"""

    step_id: str
    capability_name: str
    input_mapping: dict[str, str]  # Map workflow vars to capability inputs
    output_mapping: dict[str, str]  # Map capability outputs to workflow vars
    condition: str | None = None  # Optional conditional execution
    retry_count: int = 3
    timeout: int = 30


@dataclass
class Workflow:
    """Multi-step workflow definition"""

    workflow_id: str
    name: str
    description: str
    steps: list[WorkflowStep]
    initial_context: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class CapabilityExecutionContext:
    """Context for capability execution"""

    agent_id: str
    capability_name: str
    input_data: dict
    workflow_id: str | None = None
    step_id: str | None = None
    metadata: dict = field(default_factory=dict)


class DynamicCapabilityRegistry:
    """
    Dynamic capability registry with runtime discovery
    """

    def __init__(self):
        # Registered capabilities
        self.capabilities: dict[str, CapabilitySchema] = {}

        # Capability implementations
        self.implementations: dict[str, Callable] = {}

        # Workflows
        self.workflows: dict[str, Workflow] = {}

        # Capability dependencies graph
        self.dependency_graph: dict[str, set[str]] = {}

        # Usage metrics
        self.execution_count: dict[str, int] = {}
        self.execution_time: dict[str, list[float]] = {}

    async def register_capability(self, capability: CapabilitySchema, implementation: Callable) -> bool:
        """
        Register a new capability with implementation

        Args:
            capability: Capability schema
            implementation: Async callable implementing the capability

        Returns:
            True if registered successfully
        """
        # Validate dependencies
        for dep in capability.requires:
            if dep not in self.capabilities:
                raise ValueError(f"Missing dependency: {dep}")

        # Register capability
        self.capabilities[capability.name] = capability
        self.implementations[capability.name] = implementation

        # Update dependency graph
        self.dependency_graph[capability.name] = set(capability.requires)

        # Initialize metrics
        self.execution_count[capability.name] = 0
        self.execution_time[capability.name] = []

        print(f"✅ Capability registered: {capability.name} (v{capability.version})")

        return True

    async def discover_capabilities(
        self, agent_id: str, tags: set[str] | None = None, complexity_max: OperationComplexity | None = None
    ) -> list[CapabilitySchema]:
        """
        Discover available capabilities for an agent

        Args:
            agent_id: Agent requesting discovery
            tags: Filter by tags
            complexity_max: Maximum complexity level

        Returns:
            List of available capabilities
        """
        capabilities = list(self.capabilities.values())

        # Filter by tags
        if tags:
            capabilities = [cap for cap in capabilities if cap.tags & tags]

        # Filter by complexity
        if complexity_max:
            complexity_order = {
                OperationComplexity.SIMPLE: 0,
                OperationComplexity.MODERATE: 1,
                OperationComplexity.COMPLEX: 2,
                OperationComplexity.WORKFLOW: 3,
            }
            max_level = complexity_order[complexity_max]

            capabilities = [cap for cap in capabilities if complexity_order[cap.complexity] <= max_level]

        print(f"🔍 Discovered {len(capabilities)} capabilities for {agent_id}")

        return capabilities

    async def negotiate_capabilities(self, agent_id: str, requested_capabilities: list[str]) -> dict[str, bool]:
        """
        Negotiate which requested capabilities are available

        Args:
            agent_id: Agent requesting capabilities
            requested_capabilities: List of capability names

        Returns:
            Dict mapping capability names to availability
        """
        negotiation_result = {}

        for cap_name in requested_capabilities:
            # Check if capability exists
            if cap_name not in self.capabilities:
                negotiation_result[cap_name] = False
                continue

            capability = self.capabilities[cap_name]

            # Check if all dependencies are available
            deps_available = all(dep in self.capabilities for dep in capability.requires)

            negotiation_result[cap_name] = deps_available

        available_count = sum(negotiation_result.values())
        print(f"🤝 Negotiated {available_count}/{len(requested_capabilities)} capabilities for {agent_id}")

        return negotiation_result

    async def execute_capability(self, context: CapabilityExecutionContext) -> dict:
        """
        Execute a capability

        Args:
            context: Execution context

        Returns:
            Execution result
        """
        start_time = time.perf_counter()

        capability_name = context.capability_name

        # Verify capability exists
        if capability_name not in self.capabilities:
            raise ValueError(f"Unknown capability: {capability_name}")

        self.capabilities[capability_name]
        implementation = self.implementations[capability_name]

        # Validate input against schema
        # (Add JSON schema validation here)

        try:
            # Execute capability
            result = await implementation(context.input_data)

            # Update metrics
            self.execution_count[capability_name] += 1

            execution_time = (time.perf_counter() - start_time) * 1000
            self.execution_time[capability_name].append(execution_time)

            # Keep only last 1000 measurements
            if len(self.execution_time[capability_name]) > 1000:
                self.execution_time[capability_name] = self.execution_time[capability_name][-1000:]

            print(f"⚡ Executed {capability_name} in {execution_time:.2f}ms")

            return {"success": True, "result": result, "execution_time_ms": execution_time}

        except Exception as e:
            print(f"❌ Capability execution failed: {capability_name} - {e}")

            return {"success": False, "error": str(e), "execution_time_ms": (time.perf_counter() - start_time) * 1000}

    async def register_workflow(self, workflow: Workflow) -> bool:
        """
        Register a multi-step workflow

        Args:
            workflow: Workflow definition

        Returns:
            True if registered successfully
        """
        # Validate all steps reference existing capabilities
        for step in workflow.steps:
            if step.capability_name not in self.capabilities:
                raise ValueError(f"Unknown capability in workflow: {step.capability_name}")

        self.workflows[workflow.workflow_id] = workflow

        print(f"🔄 Workflow registered: {workflow.name} ({len(workflow.steps)} steps)")

        return True

    async def execute_workflow(self, workflow_id: str, agent_id: str, initial_input: dict) -> dict:
        """
        Execute a multi-step workflow

        Args:
            workflow_id: Workflow identifier
            agent_id: Executing agent
            initial_input: Initial workflow input

        Returns:
            Workflow execution result
        """
        start_time = time.perf_counter()

        if workflow_id not in self.workflows:
            raise ValueError(f"Unknown workflow: {workflow_id}")

        workflow = self.workflows[workflow_id]

        # Initialize workflow context
        workflow_context = {**workflow.initial_context, **initial_input}

        step_results = []

        # Execute workflow steps
        for step in workflow.steps:
            # Check condition if present
            if step.condition:
                if not self._evaluate_condition(step.condition, workflow_context):
                    print(f"⏭️  Skipping step {step.step_id} (condition not met)")
                    continue

            # Map inputs from workflow context
            step_input = {param: workflow_context.get(source_var) for param, source_var in step.input_mapping.items()}

            # Execute capability with retry
            result = None
            for attempt in range(step.retry_count):
                try:
                    context = CapabilityExecutionContext(
                        agent_id=agent_id,
                        capability_name=step.capability_name,
                        input_data=step_input,
                        workflow_id=workflow_id,
                        step_id=step.step_id,
                    )

                    result = await asyncio.wait_for(self.execute_capability(context), timeout=step.timeout)

                    if result["success"]:
                        break

                except asyncio.TimeoutError:
                    print(f"⏱️  Step {step.step_id} timed out (attempt {attempt + 1}/{step.retry_count})")

                except Exception as e:
                    print(f"❌ Step {step.step_id} failed (attempt {attempt + 1}/{step.retry_count}): {e}")

            if not result or not result["success"]:
                return {
                    "success": False,
                    "error": f"Workflow failed at step {step.step_id}",
                    "completed_steps": step_results,
                    "execution_time_ms": (time.perf_counter() - start_time) * 1000,
                }

            # Map outputs to workflow context
            if result["success"]:
                step_output = result["result"]
                for target_var, output_param in step.output_mapping.items():
                    if isinstance(step_output, dict):
                        workflow_context[target_var] = step_output.get(output_param)
                    else:
                        workflow_context[target_var] = step_output

            step_results.append(
                {
                    "step_id": step.step_id,
                    "capability": step.capability_name,
                    "success": True,
                    "result": result["result"],
                }
            )

        execution_time = (time.perf_counter() - start_time) * 1000

        print(f"✅ Workflow completed: {workflow.name} in {execution_time:.2f}ms")

        return {
            "success": True,
            "steps": step_results,
            "final_context": workflow_context,
            "execution_time_ms": execution_time,
        }

    def _evaluate_condition(self, condition: str, context: dict) -> bool:
        """
        Evaluate workflow condition

        Args:
            condition: Condition expression
            context: Workflow context

        Returns:
            True if condition is met
        """
        try:
            # Simple expression evaluation
            # In production, use a safe expression evaluator
            return eval(condition, {"__builtins__": {}}, context)
        except Exception:
            return False

    def get_capability_metrics(self, capability_name: str) -> dict:
        """Get metrics for a specific capability"""
        if capability_name not in self.capabilities:
            return {}

        exec_times = self.execution_time.get(capability_name, [])

        if not exec_times:
            return {"execution_count": 0, "avg_execution_time_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}

        exec_times_array = np.array(exec_times)

        return {
            "execution_count": self.execution_count.get(capability_name, 0),
            "avg_execution_time_ms": float(np.mean(exec_times_array)),
            "p50_ms": float(np.percentile(exec_times_array, 50)),
            "p95_ms": float(np.percentile(exec_times_array, 95)),
            "p99_ms": float(np.percentile(exec_times_array, 99)),
        }

    def get_registry_metrics(self) -> dict:
        """Get overall registry metrics"""
        total_executions = sum(self.execution_count.values())

        return {
            "registered_capabilities": len(self.capabilities),
            "registered_workflows": len(self.workflows),
            "total_executions": total_executions,
            "capabilities_by_type": {
                cap_type.value: sum(1 for cap in self.capabilities.values() if cap.type == cap_type)
                for cap_type in CapabilityType
            },
            "capabilities_by_complexity": {
                complexity.value: sum(1 for cap in self.capabilities.values() if cap.complexity == complexity)
                for complexity in OperationComplexity
            },
        }
