"""Display compatibility and accessibility across Streamlit API versions."""
from inspect import signature
import unittest

import streamlit as st
from streamlit.testing.v1 import AppTest

from src.streamlit_compat import alt_text


class AltTextTests(unittest.TestCase):
    def test_older_command_accepts_data_without_alt(self):
        def display(data, *, hide_index=False):
            return data, hide_index

        self.assertEqual(display([1], hide_index=True, **alt_text(display, 'Values')),
                         ([1], True))

    def test_newer_command_receives_accessible_label(self):
        def display(data, *, alt=None):
            return data, alt

        self.assertEqual(display([1], **alt_text(display, 'Values')), ([1], 'Values'))

    def test_arbitrary_kwargs_do_not_imply_alt_support(self):
        def display(data, **kwargs):
            return kwargs

        self.assertEqual(display([1], **alt_text(display, 'Values')), {})

    def test_real_commands_match_installed_api(self):
        for command in (st.dataframe, st.bar_chart, st.line_chart):
            with self.subTest(command=command.__name__):
                expected = {'alt': 'Values'} if 'alt' in signature(command).parameters else {}
                self.assertEqual(alt_text(command, 'Values'), expected)

    def test_charts_and_table_render_with_installed_streamlit(self):
        def script():
            import streamlit as st
            from src.streamlit_compat import alt_text

            st.dataframe({'Bytes': [1, 2]}, **alt_text(st.dataframe, 'Observed bytes'))
            st.bar_chart({'Bytes': [1, 2]}, **alt_text(st.bar_chart, 'Observed bytes'))
            st.line_chart({'Mbps': [1, 2]}, **alt_text(st.line_chart, 'Measured rates'))

        app = AppTest.from_function(script).run(timeout=15)
        self.assertFalse(app.exception, [e.message for e in app.exception])
        self.assertEqual(len(app.dataframe), 1)
        self.assertEqual(len(app.get('vega_lite_chart')), 2)


if __name__ == '__main__':
    unittest.main()
