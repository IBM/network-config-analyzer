# TODO: the experiment name should be automatically inferred from the file name + function_name.
# TODO: after writing this experiment, do some refactoring in the experiments code.
# TODO: object oriented experiments to not duplicate data.

# TODO: create the experiment with the following parts: (each in a separate figure).
# TODO: single cube with increasing number of dimensions, with increasing cube complexity.
# TODO: linear #cubes without interference between cubes
# TODO: linear #cubes with interference between cubes
# TODO: quadratic #cubes without interference between cubes
# TODO: quadratic #cubes with interference between cubes
# TODO: IDEA: I can actually get positive examples by drawing from the set, and negative samples using
#   randomization.
from typing import Union

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager
from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import EngineType, Variable, get_y_var_list
from smt_experiments.experiments.n_unions_string_experiment import BasicSet
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment, Operation
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet
from smt_experiments.z3_sets.z3_string_set import Z3StringSet


class SingleSimpleCube:
    experiment_name = 'multiple_string_dimensions_single_simple_cube'
    min_dims = 1
    max_dims = 20  # TODO: use a higher value, this is just for experimenting.
    step = 1

    @staticmethod
    def _get_contained_element(n_dims: int, basic_set: BasicSet) -> list[str]:
        element = ['0' * 5 for _ in range(n_dims)]
        if basic_set == BasicSet.PREFIX:
            element = [entry + 'xxx' for entry in element]
        if basic_set == BasicSet.SUFFIX:
            element = ['xxx' + entry for entry in element]
        return element

    def get_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        return [self._get_contained_element(n_dims, basic_set)]

    @staticmethod
    def get_not_contained_elements(engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        return [['1' * 5 for _ in range(n_dims)]]

    @staticmethod
    def get_set(engine: EngineType, n_dims: int, basic_set: BasicSet):
        if engine == EngineType.Z3:
            single_dim_set_cls = Z3StringSet
            product_set_cls = Z3ProductSet
        else:  # engine == EngineType.OUR:
            single_dim_set_cls = MinDFA
            product_set_cls = CanonicalHyperCubeSet

        dim_names = [str(i) for i in range(n_dims)]
        cube = [single_dim_set_cls.from_wildcard('0' * 5) for _ in range(n_dims)]
        representation = '{' + '0' * 5 + '} ^ ' + str(n_dims)

        return product_set_cls.create_from_cube(dim_names, cube, dim_names), representation

    def run(self):
        # TODO: extract the common operations to avoid code duplication, the list of operations
        #   are almost the same for all. maybe as some abstract property?
        #   we can actually use the same `run` method for all experiment if we define the parameters
        #   separately.
        # TODO: add expected result field, and check if it holds.
        membership_positive = Operation(
            name='positive_membership',
            get_input_list=self.get_contained_elements,
            run_operation=lambda set_0, element: element in set_0,
        )
        membership_negative = Operation(
            name='negative_membership',
            get_input_list=self.get_not_contained_elements,
            run_operation=lambda set_0, element: element in set_0,
        )
        operation_list = [
            membership_positive,
            membership_negative
        ]
        set_params_options = {
            'engine': list(EngineType),
            'n_dims': list(range(self.min_dims, self.max_dims + 1, self.step)),
            'basic_set': list(BasicSet)
        }

        dim_manager = DimensionsManager()
        for i in range(self.max_dims):
            dim_manager.set_domain(str(i), dim_manager.DimensionType.DFA)

        run_experiment(
            experiment_name=self.experiment_name,
            set_params_options=set_params_options,
            get_set_from_params=self.get_set,
            operation_list=operation_list,
        )

    def plot(self):
        x_var = Variable(
            'n_dims',
            lambda result: result['set_params']['n_dims']
        )

        horizontal_var_list = [
            Variable(
                'basic_set',
                lambda result: result['set_params']['basic_set']
            )
        ]

        legend_var_list = [
            Variable(
                'engine',
                lambda result: result['set_params']['engine']
            )
        ]
        plot_results(
            experiment_name=self.experiment_name,
            x_var=x_var,
            y_var_list=get_y_var_list(),
            horizontal_var_list=horizontal_var_list,
            legend_var_list=legend_var_list,
        )


if __name__ == '__main__':
    experiment1 = SingleSimpleCube()
    experiment1.run()
    experiment1.plot()

